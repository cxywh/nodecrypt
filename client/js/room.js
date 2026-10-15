// Room management logic for NodeCrypt web client
// NodeCrypt 网页客户端的房间管理逻辑

import {
	createAvatarSVG
} from './util.avatar.js';
import {
	renderChatArea,
	addSystemMsg,
	updateChatInputStyle
} from './chat.js';
import {
	renderMainHeader,
	renderUserList,
	setConnectStatus
} from './ui.js';
import {
	ConnectStatus,
	STAGE
} from './util.connect.js';
import {
	escapeHTML,
	computeDisplayNames,
	resolveDisplayName,
} from './util.string.js';
import {
	$id,
	createElement
} from './util.dom.js';
import { t } from './util.i18n.js';
let roomsData = [];
let activeRoomIndex = -1;

// Get a new room data object
// 获取一个新的房间数据对象
export function getNewRoomData() {
	return {
		roomName: '',
		userList: [],
		userMap: {},
		myId: null,
		myUserName: '',
		chat: null,
		messages: [],
		prevUserList: [],
		knownUserIds: new Set(),
		unreadCount: 0,
		privateChatTargetId: null,
		privateChatTargetName: null
	}
}

// Switch to another room by index
// 切换到指定索引的房间
export function switchRoom(index) {
	if (index < 0 || index >= roomsData.length) return;
	activeRoomIndex = index;
	const rd = roomsData[index];
	if (typeof rd.unreadCount === 'number') rd.unreadCount = 0;
	const sidebarUsername = document.getElementById('sidebar-username');
	if (sidebarUsername) sidebarUsername.textContent = rd.myUserName;
	setSidebarAvatar(rd.myUserName);
	renderRooms(index);
	renderMainHeader();
	renderUserList(false);
	renderChatArea();
	updateChatInputStyle()
}

// Set the sidebar avatar
// 设置侧边栏头像
export function setSidebarAvatar(userName) {
	if (!userName) return;
	const svg = createAvatarSVG(userName);
	const el = $id('sidebar-user-avatar');
	if (el) {
		const cleanSvg = svg.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
		el.innerHTML = cleanSvg
	}
}

// Render the room list
// 渲染房间列表
export function renderRooms(activeId = 0) {
	const roomList = $id('room-list');
	roomList.innerHTML = '';
	roomsData.forEach((rd, i) => {
		const div = createElement('div', {
			class: 'room' + (i === activeId ? ' active' : ''),
			onclick: () => switchRoom(i)
		});
		const safeRoomName = escapeHTML(rd.roomName);
		let unreadHtml = '';
		if (rd.unreadCount && i !== activeId) {
			unreadHtml = `<span class="room-unread-badge">${rd.unreadCount>99?'99+':rd.unreadCount}</span>`
		}
		div.innerHTML = `<div class="info"><div class="title">#${safeRoomName}</div></div>${unreadHtml}`;
		roomList.appendChild(div)
	})
}

// Join a room
// 加入一个房间
export function joinRoom(userName, roomName, password, modal = null, onResult) {
	const newRd = getNewRoomData();
	newRd.roomName = roomName;
	newRd.myUserName = userName;
	newRd.password = password;
	roomsData.push(newRd);
	const idx = roomsData.length - 1;
	switchRoom(idx);
	const sidebarUsername = $id('sidebar-username');
	if (sidebarUsername) sidebarUsername.textContent = userName;
	setSidebarAvatar(userName);
	// 连接过程的可见反馈。带秒数是关键 —— 实测这条链路握手 0.5~10 秒抖动，
	// 静态的「连接中...」无法区分「正在连」和「已经卡死」。
	const status = new ConnectStatus({
		onRender: (state) => setConnectStatus(state),
		// 超时也要让按钮恢复可点，否则用户只能刷新页面。
		onTimeout: () => settle(false)
	});
	// 单次收尾。这是这次改动最关键的一处：
	//
	// 原来 onServerClosed 的第一行是 setStatus('Node connection closed')，
	// 而这个函数在整个项目里**只有调用、没有定义**。它抛出的 ReferenceError
	// 被 NodeCrypt 的 try/catch 吞掉（只在 debug 日志里留一行），
	// 于是紧随其后的 onResult(false) 永远执行不到 ——
	// 连接失败时按钮永远停在「连接中...」，用户看不到任何错误，只能刷新页面。
	//
	// 现在收尾不依赖任何可能抛错的调用，而且幂等：
	// NodeCrypt 的 onError 和 onClose 会先后都调 onServerClosed。
	let settled = false;
	function settle(ok) {
		if (settled) {
			return
		}
		settled = true;
		status.stop();
		if (!onResult) {
			return
		}
		try {
			onResult(ok)
		} catch (error) {
			// 回调里抛错不该让连接状态卡住，但必须可见。
			console.error('joinRoom onResult failed:', error)
		}
	}
	const callbacks = {
		// 取 Turnstile token 期间切到不计时的 stage：这段等的是人，不是网。
		// 拿回 token 后 status.start() 会重新起算，秒数不会把点击耗时算进去。
		onVerifyNeeded: () => status.waitForVerify(),
		onVerifyDone: () => status.start(),
		// 验证没完成：报一个明确的失败（不是「连接失败」——那次根本没去连），
		// 并把按钮交还给用户，让他重新点「确定」拿一枚新挑战。
		onVerifyFailed: () => { status.fail('verify'); settle(false); },
		// WebSocket 握手成功 —— 网络这一段结束，接下来是密钥协商。
		// 分开报是为了让用户知道慢在哪一段。
		onSocketOpen: () => status.advance(STAGE.CRYPTO),
		onServerClosed: (reason) => {
			if (settled) {
				// 连上之后才断线。这时登录表单已经隐藏，改状态行用户也看不见 ——
				// 该说的是聊天区里的一句话。
				if (status.stage === STAGE.READY) {
					status.stop();
					addSystemMsg(t('system.disconnected', 'disconnected from server'))
				}
				return
			}
			status.fail(reason || 'closed');
			settle(false)
		},
		onServerSecured: () => {
			status.finish();
			if (modal) {
				modal.remove()
			} else {
				const loginContainer = $id('login-container');
				if (loginContainer) loginContainer.style.display = 'none';
				const chatContainer = $id('chat-container');
				if (chatContainer) chatContainer.style.display = '';
			}
			settle(true);
			addSystemMsg(t('system.secured', 'connection secured'))
		},
		// 服务端业务拒绝（房间满）。不是网络故障 —— 直接停在失败态、把原因
		// 说清楚，绝不重连（NodeCrypt 侧已置 _rejected）。fail() 是幂等的，
		// 紧随其后的 onServerClosed 不会再改这条文案。
		onServerError: (code, limit) => {
			if (code === 'room-full') {
				status.fail(t('system.room_full', 'Room is full (limit ' + limit + ')'))
			} else {
				status.fail(code || 'server rejected')
			}
			settle(false)
		},
		onClientSecured: (user) => handleClientSecured(idx, user),
		onClientList: (list, selfId) => handleClientList(idx, list, selfId),
		onClientLeft: (clientId) => handleClientLeft(idx, clientId),
		onClientMessage: (msg) => handleClientMessage(idx, msg),
		// 二进制通道：文件分卷走这里，不经过上面的 JSON 信封。
		// （发送方向不走这里 —— 由 main.js 传给 setupFileSend 的 onSendBinary 负责，
		//   因为 NodeCrypt 的 callbacks 里没有发送类回调。）
		onBinaryData: (record) => window.handleBinaryVolume?.(record)
	};
	status.start();
	const chatInst = new window.NodeCrypt(window.config, callbacks);
	chatInst.setCredentials(userName, roomName, password);
	chatInst.connect();
	roomsData[idx].chat = chatInst
}

// 重算房间级显示名。成员名单或成员信息变化后调用，这是唯一的刷新入口。
// 重名在这里被消歧，其余所有取名字的地方都走 resolveDisplayName。
// 服务端下发的成员名单逐人剔除接收者自己（worker 的 broadcastMemberList），
// 因此这里补上自身条目，否则「我」与同名成员之间不会消歧。
function refreshDisplayNames(rd) {
	if (!rd) return;
	const entries = (rd.userList || []).slice();
	if (rd.myId && rd.myUserName) entries.push({ clientId: rd.myId, userName: rd.myUserName });
	rd.displayNames = computeDisplayNames(entries, t('ui.anonymous', 'Anonymous'));
}

// Handle the client list update
// 处理客户端列表更新
export function handleClientList(idx, list, selfId) {
	const rd = roomsData[idx];
	if (!rd) return;
	const oldUserIds = new Set((rd.userList || []).map(u => u.clientId));
	const newUserIds = new Set(list.map(u => u.clientId));
	for (const oldId of oldUserIds) {
		if (!newUserIds.has(oldId)) {
			handleClientLeft(idx, oldId)
		}
	}
	rd.userList = list;
	rd.userMap = {};
	refreshDisplayNames(rd);
	list.forEach(u => {
		rd.userMap[u.clientId] = u
	});
	rd.myId = selfId;
	if (activeRoomIndex === idx) {
		renderUserList(false);
		renderMainHeader()
	}
	rd.initCount = (rd.initCount || 0) + 1;
	if (rd.initCount === 2) {
		rd.isInitialized = true;
		rd.knownUserIds = new Set(list.map(u => u.clientId))
	}
}

// Handle client secured event
// 处理客户端安全连接事件
export function handleClientSecured(idx, user) {
	const rd = roomsData[idx];
	if (!rd) return;
	rd.userMap[user.clientId] = user;
	const existingUserIndex = rd.userList.findIndex(u => u.clientId === user.clientId);
	if (existingUserIndex === -1) {
		rd.userList.push(user)
	} else {
		rd.userList[existingUserIndex] = user
	}
	refreshDisplayNames(rd);
	if (activeRoomIndex === idx) {
		renderUserList(false);
		renderMainHeader()
	}
	if (!rd.isInitialized) {
		return
	}
	const isNew = !rd.knownUserIds.has(user.clientId);
	if (isNew) {
		rd.knownUserIds.add(user.clientId);
		const name = resolveDisplayName(rd, user.clientId, t('ui.anonymous', 'Anonymous'));
		const msg = `${name} ${t('system.joined', 'joined the conversation')}`;
		rd.messages.push({
			type: 'system',
			text: msg
		});
		if (activeRoomIndex === idx) addSystemMsg(msg, true);
		if (window.notifyMessage) {
			window.notifyMessage(rd.roomName, 'system', msg)
		}
	}
}

// Handle client left event
// 处理客户端离开事件
export function handleClientLeft(idx, clientId) {
	const rd = roomsData[idx];
	if (!rd) return;
	if (rd.privateChatTargetId === clientId) {
		rd.privateChatTargetId = null;
		rd.privateChatTargetName = null;
		if (activeRoomIndex === idx) {
			updateChatInputStyle()
		}
	}
	const name = resolveDisplayName(rd, clientId, t('ui.anonymous', 'Anonymous'));
	const msg = `${name} ${t('system.left', 'left the conversation')}`;
	rd.messages.push({
		type: 'system',
		text: msg
	});
	if (activeRoomIndex === idx) addSystemMsg(msg, true);
	rd.userList = rd.userList.filter(u => u.clientId !== clientId);
	delete rd.userMap[clientId];
	refreshDisplayNames(rd);
	if (activeRoomIndex === idx) {
		renderUserList(false);
		renderMainHeader()
	}
}

// Handle client message event
// 处理客户端消息事件
export function handleClientMessage(idx, msg) {
	const newRd = roomsData[idx];
	if (!newRd) return;

	// Prevent processing own messages unless it's a private message sent to oneself
	if (msg.clientId === newRd.myId && msg.userName === newRd.myUserName && !msg.type.includes('_private')) {
		return;
	}

	let msgType = msg.type || 'text';

	// Handle file messages
	if (msgType.startsWith('file_')) {
		// Part 1: Update message history and send notifications (for 'file_start' type)
		// file_offer 是 R2 大文件的清单，语义等价于 file_start（都是「来了一个文件」），
		// 所以走同一套：进历史、发通知、在非当前房间加未读。
		if (msgType === 'file_start' || msgType === 'file_start_private'
			|| msgType === 'file_offer' || msgType === 'file_offer_private') {
			let realUserName = msg.userName;
			if (!realUserName && msg.clientId && newRd.userMap[msg.clientId]) {
				realUserName = resolveDisplayName(newRd, msg.clientId, t('ui.anonymous', 'Anonymous'));
			}
			const historyMsgType = (msgType === 'file_start_private' || msgType === 'file_offer_private') ? 'file_private' : 'file';
			
			const fileId = msg.data && msg.data.fileId;
			if (fileId) { // Only proceed if we have a fileId
				const messageAlreadyInHistory = newRd.messages.some(
					m => m.msgType === historyMsgType && m.text && m.text.fileId === fileId && m.userName === realUserName
				);

				if (!messageAlreadyInHistory) {
					newRd.messages.push({
						type: 'other',
						text: msg.data, // This is the file metadata object
						userName: realUserName,
						avatar: realUserName,
						msgType: historyMsgType,
						timestamp: (msg.data && msg.data.timestamp) || Date.now() 
					});
				}
			}

			const notificationMsgType = msgType.includes('_private') ? 'private file' : 'file';
			if (window.notifyMessage && msg.data && msg.data.fileName) {
				window.notifyMessage(newRd.roomName, notificationMsgType, `${msg.data.fileName}`, realUserName);
			}
		}

		// Part 2: Handle UI interaction (rendering in active room, or unread count in inactive room)
		if (activeRoomIndex === idx) {
			// If it's the active room, delegate to util.file.js to handle UI and file transfer state.
			// This applies to all file-related messages (file_start, file_volume, file_end, etc.)
			if (window.handleFileMessage) {
				window.handleFileMessage(msg.data, msgType.includes('_private'));
			}
		} else {
			// If it's not the active room, only increment unread count for 'file_start' messages.
			if (msgType === 'file_start' || msgType === 'file_start_private'
				|| msgType === 'file_offer' || msgType === 'file_offer_private') {
				newRd.unreadCount = (newRd.unreadCount || 0) + 1;
				renderRooms(activeRoomIndex);
			}
		}
		return; // File messages are fully handled.
	}

	// Handle image messages (both new and legacy formats)
	if (msgType === 'image' || msgType === 'image_private') {
		// Already has correct type
	} else if (!msgType.includes('_private')) {
		// Handle legacy image detection
		if (msg.data && typeof msg.data === 'string' && msg.data.startsWith('data:image/')) {
			msgType = 'image';
		} else if (msg.data && typeof msg.data === 'object' && msg.data.image) {
			msgType = 'image';
		}
	}
	let realUserName = msg.userName;
	if (!realUserName && msg.clientId && newRd.userMap[msg.clientId]) {
		realUserName = resolveDisplayName(newRd, msg.clientId, t('ui.anonymous', 'Anonymous'));
	}

	// Add message to messages array for chat history
	roomsData[idx].messages.push({
		type: 'other',
		text: msg.data,
		userName: realUserName,
		avatar: realUserName,
		msgType: msgType,
		timestamp: Date.now()
	});

	// Only add message to chat display if it's for the active room
	if (activeRoomIndex === idx) {
		if (window.addOtherMsg) {
			window.addOtherMsg(msg.data, realUserName, realUserName, false, msgType);
		}
	} else {
		roomsData[idx].unreadCount = (roomsData[idx].unreadCount || 0) + 1;
		renderRooms(activeRoomIndex);
	}

	const notificationMsgType = msgType.includes('_private') ? `private ${msgType.split('_')[0]}` : msgType;
	if (window.notifyMessage) {
		window.notifyMessage(newRd.roomName, notificationMsgType, msg.data, realUserName);
	}
}

// Toggle private chat with a user
// 切换与某用户的私聊
export function togglePrivateChat(targetId, targetName) {
	const rd = roomsData[activeRoomIndex];
	if (!rd) return;
	if (rd.privateChatTargetId === targetId) {
		rd.privateChatTargetId = null;
		rd.privateChatTargetName = null
	} else {
		rd.privateChatTargetId = targetId;
		rd.privateChatTargetName = targetName
	}
	renderUserList();
	updateChatInputStyle()
}


// Exit the current room
// 退出当前房间
export function exitRoom() {
	if (activeRoomIndex >= 0 && roomsData[activeRoomIndex]) {
		const chatInst = roomsData[activeRoomIndex].chat;
		if (chatInst && typeof chatInst.destruct === 'function') {
			chatInst.destruct()
		} else if (chatInst && typeof chatInst.disconnect === 'function') {
			chatInst.disconnect()
		}
		roomsData[activeRoomIndex].chat = null;
		roomsData.splice(activeRoomIndex, 1);
		if (roomsData.length > 0) {
			switchRoom(0);
			return true
		} else {
			return false
		}
	}
	return false
}

export { roomsData, activeRoomIndex };

// Listen for sidebar username update event
// 监听侧边栏用户名更新事件
window.addEventListener('updateSidebarUsername', () => {
	if (activeRoomIndex >= 0 && roomsData[activeRoomIndex]) {
		const rd = roomsData[activeRoomIndex];
		const sidebarUsername = document.getElementById('sidebar-username');
		if (sidebarUsername && rd.myUserName) {
			sidebarUsername.textContent = rd.myUserName;
		}
		// Also update the avatar to ensure consistency
		if (rd.myUserName) {
			setSidebarAvatar(rd.myUserName);
		}
	}
});