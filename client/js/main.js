// 导入 NodeCrypt 模块（加密功能模块）
// Import the NodeCrypt module (used for encryption)
import './NodeCrypt.js';

// 从 util.file.js 中导入设置文件发送的函数
// Import setupFileSend function from util.file.js
import {
	setupFileSend,
	handleFileMessage,
	handleBinaryVolume,
	downloadFile
} from './util.file.js';

// 从 util.image.js 中导入图片处理功能
// Import image processing functions from util.image.js
import {
	setupImagePaste
} from './util.image.js';

// 从 util.emoji.js 中导入设置表情选择器的函数
// Import setupEmojiPicker function from util.emoji.js
import {
	setupEmojiPicker
} from './util.emoji.js';

// 从 util.settings.js 中导入设置面板的功能函数
// Import functions for settings panel from util.settings.js
import {
	openSettingsPanel,   // 打开设置面板 / Open settings panel
	closeSettingsPanel,  // 关闭设置面板 / Close settings panel
	initSettings,         // 初始化设置 / Initialize settings
	notifyMessage         // 通知信息提示 / Display notification message
} from './util.settings.js';
import { t, updateStaticTexts } from './util.i18n.js';

// 从 util.theme.js 中导入主题功能函数
// Import theme functions from util.theme.js
import {
	initTheme            // 初始化主题 / Initialize theme
} from './util.theme.js';

// 从 util.dom.js 中导入常用 DOM 操作函数
// Import common DOM manipulation functions from util.dom.js
import {
	$,         // 简化的 document.querySelector / Simplified selector
	$id,       // document.getElementById 的简写 / Shortcut for getElementById
	removeClass // 移除类名 / Remove a CSS class
} from './util.dom.js';

// 从 room.js 中导入房间管理相关变量和函数
// Import room-related variables and functions from room.js
import {
	roomsData,         // 当前所有房间的数据 / Data of all rooms
	activeRoomIndex,   // 当前激活的房间索引 / Index of the active room
	joinRoom           // 加入房间的函数 / Function to join a room
} from './room.js';

// 从 chat.js 中导入聊天功能相关的函数
// Import chat-related functions from chat.js
import {
	addMsg,               // 添加普通消息到聊天窗口 / Add a normal message to chat
	addOtherMsg,          // 添加其他用户消息 / Add message from other users
	addSystemMsg,         // 添加系统消息 / Add a system message
	setupImagePreview,    // 设置图片预览功能 / Setup image preview
	setupInputPlaceholder, // 设置输入框的占位提示 / Setup placeholder for input box
	autoGrowInput         // 自动调整输入框高度 / Auto adjust input height
} from './chat.js';

// 从 ui.js 中导入 UI 界面相关的功能
// Import user interface functions from ui.js
import {	renderUserList,       // 渲染用户列表 / Render user list
	renderMainHeader,     // 渲染主标题栏 / Render main header
	setupMoreBtnMenu,     // 设置更多按钮的下拉菜单 / Setup "more" button menu
	preventSpaceInput,    // 防止输入空格 / Prevent space input in form fields
	loginFormHandler,     // 登录表单提交处理器 / Login form handler
	openLoginModal,       // 打开登录窗口 / Open login modal
	setupTabs,            // 设置页面标签切换 / Setup tab switching
	autofillRoomPwd,      // 自动填充房间密码 / Autofill room password
	generateLoginForm,    // 生成登录表单HTML / Generate login form HTML
	initLoginForm,        // 初始化登录表单 / Initialize login form
	initFlipCard          // 初始化翻转卡片功能 / Initialize flip card functionality
} from './ui.js';

// 设置全局配置参数
// Set global configuration parameters
window.config = {
	wsAddress: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`, // WebSocket 服务器地址 / WebSocket server address
	//wsAddress: `wss://crypt.works`,
	// 生产环境关掉 debug：开着的话 NodeCrypt 会把每条收到的帧打进控制台，
	// 单条可达数百 KB，既刷屏（用户明确要求日志干净）又把用户数据落到控制台日志里。
	// 需要排查时在地址栏加 ?debug=1；本地开发自动打开。
	// Turnstile 人机验证的 sitekey（公开值，可以放在前端）。
	// 留空 = 不启用，连接行为与接入前一致。widget 私钥在服务端 TURNSTILE_SECRET。
	turnstileSitekey: '0x4AAAAAAFW4qOG4Iz-1nyQn',
	debug: new URLSearchParams(window.location.search).has('debug') ||
		/^(localhost|127\.0\.0\.1|\[::1\])$/.test(window.location.hostname)
};

// 在文档开始加载前就初始化语言设置，防止闪烁
// Initialize language settings before document starts loading
initSettings();
updateStaticTexts();

// 把一些函数挂载到 window 对象上供其他模块使用
// Expose functions to the global window object for accessibility
window.addSystemMsg = addSystemMsg;
window.addOtherMsg = addOtherMsg;
window.addMsg = addMsg;
window.joinRoom = joinRoom;
window.notifyMessage = notifyMessage;
window.setupEmojiPicker = setupEmojiPicker;
window.handleFileMessage = handleFileMessage;
// 二进制通道的分卷入站口。room.js 里注册的 onBinaryData 回调最终落到这里。
window.handleBinaryVolume = handleBinaryVolume;
window.downloadFile = downloadFile;

// 当 DOM 内容加载完成后执行初始化逻辑
// Run initialization logic when the DOM content is fully loaded
// 加密能力预检。
// crypto.subtle 只在安全上下文（HTTPS 或 localhost）中存在；部分内嵌浏览器
// （QQ、微信等 WebView）虽然提供该对象，却缺少 HKDF 等派生算法。任一前提不满足时，
// 密钥协商会失败，而失败发生在异步链路中不会冒泡到界面，用户只会看到“连接超时”。
// 因此进入房间之前逐项探测本项目实际使用的原语，缺失时给出可操作的提示。
// 探测项集中声明，新增一项只增加一个数组元素。
const CRYPTO_PROBES = [
	['sha-256', (subtle, bytes) => subtle.digest('SHA-256', bytes(1))],
	['hkdf', async (subtle, bytes) => {
		const key = await subtle.importKey('raw', bytes(16), 'HKDF', false, ['deriveBits']);
		await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: bytes(16), info: bytes(1) }, key, 128);
	}],
	['pbkdf2', async (subtle, bytes) => {
		const key = await subtle.importKey('raw', bytes(16), 'PBKDF2', false, ['deriveBits']);
		await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: bytes(16), iterations: 1000 }, key, 128);
	}],
	['ecdh-p256', async (subtle, bytes) => {
		const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
		await subtle.deriveBits({ name: 'ECDH', public: pair.publicKey }, pair.privateKey, 256);
	}],
	['aes-256-gcm', async (subtle, bytes) => {
		const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
		const iv = bytes(12);
		const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes(1));
		await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
	}]
];

async function checkCryptoCapabilities() {
	const missing = [];
	if (!window.isSecureContext) missing.push('secure-context');
	const subtle = window.crypto && window.crypto.subtle;
	if (!subtle) {
		missing.push('webcrypto');
		return missing;
	}
	const bytes = (length) => new Uint8Array(length);
	for (const [name, probe] of CRYPTO_PROBES) {
		try {
			await probe(subtle, bytes);
		} catch (err) {
			missing.push(name);
		}
	}
	return missing;
}

// 把登录卡内容替换为原因提示。技术明细只写进控制台，便于排查，不展示给用户。
function showCryptoUnsupported(missing, form) {
	console.warn('[NodeCrypt] crypto capability check failed:', missing.join(', '));
	if (!form) return;
	const notice = document.createElement('div');
	notice.className = 'capability-notice';
	notice.textContent = t('ui.crypto_unsupported', '\u5f53\u524d\u6d4f\u89c8\u5668\u7f3a\u5c11\u5efa\u7acb\u8fde\u63a5\u6240\u9700\u7684\u52a0\u5bc6\u80fd\u529b\u3002\u8bf7\u6539\u7528\u7cfb\u7edf\u81ea\u5e26\u6d4f\u89c8\u5668\u6253\u5f00\u672c\u9875\u9762\u3002');
	form.textContent = '';
	form.appendChild(notice);
}

window.addEventListener('DOMContentLoaded', () => {
	// 移除预加载样式类，允许过渡效果
	// Remove preload class to allow transitions
	setTimeout(() => {
		document.body.classList.remove('preload');
	}, 300);
	
	// 初始化登录表单 / Initialize login form
	initLoginForm();

	const loginForm = $id('login-form');               // 登录表单 / Login form

	// 加密能力预检不通过时不再挂载提交处理，直接把登录卡换成原因提示。
	// 若照常挂载，用户在缺少加密能力的浏览器里提交后只会看到“连接超时”，
	// 无法判断是浏览器的问题，会反复重试。
	checkCryptoCapabilities().then((missing) => {
		if (missing.length) {
			showCryptoUnsupported(missing, loginForm);
			return;
		}
		if (loginForm) {
			// 监听登录表单提交事件 / Listen to login form submission
			loginForm.addEventListener('submit', loginFormHandler(null))
		}
	});

	const joinBtn = $('.join-room'); // 加入房间按钮 / Join room button
	if (joinBtn) {
		joinBtn.onclick = openLoginModal; // 点击打开登录窗口 / Click to open login modal
	}
	// 阻止用户输入用户名、房间名和密码时输入空格
	// Prevent space input for username, room name, and password fields
	preventSpaceInput($id('userName'));
	preventSpaceInput($id('roomName'));
	preventSpaceInput($id('password'));
	
	// 初始化翻转卡片功能 / Initialize flip card functionality
	initFlipCard();
	
	// 初始化辅助功能和界面设置
	// Initialize autofill, input placeholders, and menus
	autofillRoomPwd();	setupInputPlaceholder();
	setupMoreBtnMenu();
	setupImagePreview();	setupEmojiPicker();
	// 由于我们已经在DOM加载前预先初始化了语言设置，这里不需要重复初始化
	// initSettings();
	// updateStaticTexts(); // 在初始化设置后更新静态文本 / Update static texts after initializing settings
	initTheme(); // 初始化主题 / Initialize theme
	
	const settingsBtn = $id('settings-btn'); // 设置按钮 / Settings button
	if (settingsBtn) {
		settingsBtn.onclick = (e) => {
			e.stopPropagation();  // 阻止事件冒泡 / Stop event from bubbling
			openSettingsPanel(); // 打开设置面板 / Open settings panel
		}
	}

	// 设置返回按钮事件处理 / Settings back button event handler
	const settingsBackBtn = $id('settings-back-btn');
	if (settingsBackBtn) {
		settingsBackBtn.onclick = (e) => {
			e.stopPropagation();
			closeSettingsPanel(); // 关闭设置面板 / Close settings panel
		}
	}
	// 点击其他地方时关闭设置面板 (已移除，因为现在使用侧边栏形式)
	// Close settings panel when clicking outside (removed since we now use sidebar format)
	const input = document.querySelector('.input-message-input'); // 消息输入框 / Message input box
	
	// 设置图片粘贴功能
	// Setup image paste functionality
	const imagePasteHandler = setupImagePaste('.input-message-input');
	
	if (input) {
		input.focus(); // 自动聚焦 / Auto focus
		input.addEventListener('keydown', (e) => {
			// 按下 Enter 键并且不按 Shift，表示发送消息
			// Pressing Enter (without Shift) sends the message
			if (e.key === 'Enter' && !e.shiftKey) {
				e.preventDefault();
				sendMessage();
			}
		});
	}
	
	// 发送消息的统一函数
	// Unified function to send messages
	async function sendMessage() {
		const text = input.innerText.trim(); // 获取输入的文本 / Get input text
		const images = imagePasteHandler ? imagePasteHandler.getCurrentImages() : []; // 获取所有图片

		if (!text && images.length === 0) return; // 如果没有文本且没有图片，则不发送
		const rd = roomsData[activeRoomIndex]; // 当前房间数据 / Current room data
		
		if (rd && rd.chat) {
			if (images.length > 0) {
				// 发送包含图片的消息 (支持多图和文字合并)
				// Send message with images (supports multiple images and text combined)
				const messageContent = {
					text: text || '', // 包含文字内容，如果有的话
					images: images    // 包含所有图片数据
				};

				if (rd.privateChatTargetId) {
					// 私聊图片消息加密并发送
					// Encrypt and send private image message
					const targetClient = rd.chat.channel[rd.privateChatTargetId];
					if (targetClient && targetClient.shared) {
						const clientMessagePayload = {
							a: 'm',
							t: 'image_private',
							d: messageContent
						};
						const encryptedClientMessage = await rd.chat.encryptClientMessage(clientMessagePayload, targetClient.shared);
						const serverRelayPayload = {
							a: 'c',
							p: encryptedClientMessage,
							c: rd.privateChatTargetId
						};
						const encryptedMessageForServer = await rd.chat.encryptServerMessage(serverRelayPayload, rd.chat.serverShared);						rd.chat.sendMessage(encryptedMessageForServer);
						addMsg(messageContent, false, 'image_private');
					} else {
						addSystemMsg(`${t('system.private_message_failed', 'Cannot send private message to')} ${rd.privateChatTargetName}. ${t('system.user_not_connected', 'User might not be fully connected.')}`)
					}
				} else {
					// 公共频道图片消息发送
					// Send image message to public channel
					rd.chat.sendChannelMessage('image', messageContent);
					addMsg(messageContent, false, 'image');
				}
				
				imagePasteHandler.clearImages(); // 清除所有图片预览
			} else if (text) {
				// 发送纯文本消息
				// Send text-only message
				if (rd.privateChatTargetId) {
					// 私聊消息加密并发送
					// Encrypt and send private message
					const targetClient = rd.chat.channel[rd.privateChatTargetId];
					if (targetClient && targetClient.shared) {
						const clientMessagePayload = {
							a: 'm',
							t: 'text_private',
							d: text
						};
						const encryptedClientMessage = await rd.chat.encryptClientMessage(clientMessagePayload, targetClient.shared);
						const serverRelayPayload = {
							a: 'c',
							p: encryptedClientMessage,
							c: rd.privateChatTargetId
						};
						const encryptedMessageForServer = await rd.chat.encryptServerMessage(serverRelayPayload, rd.chat.serverShared);
						rd.chat.sendMessage(encryptedMessageForServer);					addMsg(text, false, 'text_private');
					} else {
						addSystemMsg(`${t('system.private_message_failed', 'Cannot send private message to')} ${rd.privateChatTargetName}. ${t('system.user_not_connected', 'User might not be fully connected.')}`)
					}
				} else {
					// 公共频道消息发送
					// Send public message
					rd.chat.sendChannelMessage('text', text);
					addMsg(text);				}
			}
			
			// 清空输入框并触发 input 事件
			// Clear input and trigger input event
			input.innerHTML = ''; // 清空输入框内容 / Clear input field content
			if (imagePasteHandler && typeof imagePasteHandler.refreshPlaceholder === 'function') {
				imagePasteHandler.refreshPlaceholder(); // 更新 placeholder 状态
			}
			autoGrowInput(); // 调整输入框高度
		}
	}
	
	// 为发送按钮添加点击事件
	// Add click event for send button
	const sendButton = document.querySelector('.send-message-btn');
	if (sendButton) {
		sendButton.addEventListener('click', sendMessage);
	}
	
	// 设置发送文件功能
	// Setup file sending functionality
	setupFileSend({
		inputSelector: '.input-message-input', // 消息输入框选择器 / Message input selector
		attachBtnSelector: '.chat-attach-btn', // 附件按钮选择器 / Attach button selector
		fileInputSelector: '.new-message-wrapper input[type="file"]', // 文件输入框选择器 / File input selector
		onSend: async (message) => {
			const rd = roomsData[activeRoomIndex];
			if (rd && rd.chat) {
				const userName = rd.myUserName || '';
				const msgWithUser = { ...message, userName };
				if (rd.privateChatTargetId) {
					// 私聊文件加密并发送
					// Encrypt and send private file message
					const targetClient = rd.chat.channel[rd.privateChatTargetId];
					if (targetClient && targetClient.shared) {
						const clientMessagePayload = {
							a: 'm',
							t: msgWithUser.type + '_private',
							d: msgWithUser
						};
						const encryptedClientMessage = await rd.chat.encryptClientMessage(clientMessagePayload, targetClient.shared);
						const serverRelayPayload = {
							a: 'c',
							p: encryptedClientMessage,
							c: rd.privateChatTargetId
						};
						const encryptedMessageForServer = await rd.chat.encryptServerMessage(serverRelayPayload, rd.chat.serverShared);
						rd.chat.sendMessage(encryptedMessageForServer);
						
						// 添加到自己的聊天记录
						if (msgWithUser.type === 'file_start') {
							addMsg(msgWithUser, false, 'file_private');
						}					} else {
						addSystemMsg(`${t('system.private_file_failed', 'Cannot send private file to')} ${rd.privateChatTargetName}. ${t('system.user_not_connected', 'User might not be fully connected.')}`)
					}
				} else {
					// 公共频道文件发送
					// Send file to public channel
					rd.chat.sendChannelMessage(msgWithUser.type, msgWithUser);
					
					// 添加到自己的聊天记录
					if (msgWithUser.type === 'file_start') {
						addMsg(msgWithUser, false, 'file');
					}
				}
			}
		},
		// 分卷走二进制通道 —— 只有这一条路能吃到 0.017% 的链路膨胀。
		// 私聊时必须带 targetClientId：不带的话密文会广播给全房间。
		onSendBinary: async (record) => {
			const rd = roomsData[activeRoomIndex];
			if (rd && rd.chat) {
				await rd.chat.sendChannelBinary(record, rd.privateChatTargetId || null);
			}
		}
	});


	// 判断是否为移动端
	// Check if the device is mobile
	const isMobile = () => window.innerWidth <= 768;

	// 渲染主界面元素
	// Render main UI elements
	renderMainHeader();
	renderUserList();
	setupTabs();

	const roomList = $id('room-list');
	const sidebar = $id('sidebar');
	const rightbar = $id('rightbar');
	const sidebarMask = $id('mobile-sidebar-mask');
	const rightbarMask = $id('mobile-rightbar-mask');

	// 在移动端点击房间列表后关闭侧边栏
	// On mobile, clicking room list closes sidebar
	if (roomList) {
		roomList.addEventListener('click', () => {
			if (isMobile()) {
				sidebar?.classList.remove('mobile-open');
				sidebarMask?.classList.remove('active');
			}
		});
	}

	// 在移动端点击成员标签后关闭右侧面板
	// On mobile, clicking member tabs closes right panel
	const memberTabs = $id('member-tabs');
	if (memberTabs) {
		memberTabs.addEventListener('click', () => {
			if (isMobile()) {
				removeClass(rightbar, 'mobile-open');
				removeClass(rightbarMask, 'active');
			}
		});
	}
});

// Listen for language change events
// 监听语言切换事件
window.addEventListener('languageChange', (event) => {
	updateStaticTexts();
});

// 全局拖拽文件自动打开附件功能
// Global drag file to auto trigger attach button
let dragCounter = 0;
let hasTriggeredAttach = false;

// 监听文件上传模态框关闭事件，重置拖拽标志位
window.addEventListener('fileUploadModalClosed', () => {
	hasTriggeredAttach = false;
});

document.addEventListener('dragenter', (e) => {
	dragCounter++;
	if (!hasTriggeredAttach && e.dataTransfer.items.length > 0) {
		// 检查是否有文件
		for (let item of e.dataTransfer.items) {
			if (item.kind === 'file') {
				// 自动点击附件按钮
				const attachBtn = document.querySelector('.chat-attach-btn');
				if (attachBtn) {
					attachBtn.click();
					hasTriggeredAttach = true;
				}
				break;
			}
		}
	}
});

document.addEventListener('dragleave', (e) => {
	dragCounter--;
	if (dragCounter === 0) {
		hasTriggeredAttach = false;
	}
});

document.addEventListener('dragover', (e) => {
	e.preventDefault();
});

document.addEventListener('drop', (e) => {
	e.preventDefault();
	dragCounter = 0;
	hasTriggeredAttach = false;
});
