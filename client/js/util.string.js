// Use DOMPurify to safely handle HTML content
// 使用 DOMPurify 安全处理 HTML 内容
import DOMPurify from 'dompurify';

// Escape HTML special characters
// 转义 HTML 特殊字符
export function escapeHTML(str) {
	if (typeof str !== 'string') return '';
	// 使用替换方法确保 HTML 特殊字符被转义，而不是被移除
	// 这样 <java> 会变成 &lt;java&gt; 而不是被删除
	return str.replace(/[&<>"']/g, function(c) {
		return {
			'&': '&amp;',  // & 转为 &amp;
			'<': '&lt;',   // < 转为 &lt;
			'>': '&gt;',   // > 转为 &gt;
			'"': '&quot;', // " 转为 &quot;
			"'": '&#39;'   // ' 转为 &#39;
		}[c];
	});
}

// Convert text to HTML, preserving line breaks
// 将文本转换为 HTML，保留换行符
export function textToHTML(text) {
	if (typeof text !== 'string') return '';
	// 先进行 HTML 转义，然后将换行符替换为 <br> 标签
	// 最后使用 DOMPurify 确保结果是安全的 HTML
	const escaped = escapeHTML(text);
	const withLineBreaks = escaped.replace(/\n/g, '<br>');
	return DOMPurify.sanitize(withLineBreaks, {
		ALLOWED_TAGS: ['br'], // 只允许 <br> 标签
		ALLOWED_ATTR: [],     // 不允许任何属性
	});
}

// 房间内显示名的统一出口。
//
// 昵称不经过服务器（通过客户端之间的加密通道交换），因此无法在入房时拒绝重名。
// 重名时在显示上附加序号：否则成员列表与消息署名完全无法区分发送者，
// 而昵称就是这套系统里唯一的身份标识。序号按 clientId 升序分配，
// 保证所有客户端对同一份名单算出完全一致的标签。
export function computeDisplayNames(userList, fallback) {
	const labels = {};
	const counts = new Map();
	// 用与区域设置无关的比较：localeCompare 在不同语言环境下的顺序可能不同，
	// 那会让两个客户端对同一份名单算出不同的标签。
	const sorted = (userList || []).slice().sort(function(a, b) {
		const x = String(a.clientId), y = String(b.clientId);
		return x < y ? -1 : (x > y ? 1 : 0);
	});
	for (const user of sorted) {
		const raw = rawUserName(user);
		const key = raw.toLowerCase();
		const seen = (counts.get(key) || 0) + 1;
		counts.set(key, seen);
		const base = raw || fallback;
		labels[user.clientId] = seen === 1 ? base : base + ' (' + seen + ')';
	}
	return labels;
}

// 取显示名。命中顺序：房间级重名消歧结果、成员自身的名字、兜底文案。
export function resolveDisplayName(roomsDataLite, clientId, fallback) {
	if (!roomsDataLite) return fallback;
	const labels = roomsDataLite.displayNames;
	if (labels && labels[clientId]) return labels[clientId];
	const user = roomsDataLite.userMap && roomsDataLite.userMap[clientId];
	const raw = rawUserName(user);
	return raw || fallback;
}

// 成员对象的昵称字段历史上有三个拼写，统一在这里取。
export function rawUserName(user) {
	if (!user) return '';
	return String(user.userName || user.username || user.name || '').trim();
}

// 校验 fileId 是否符合生成器产出的字符集。
// fileId 来自对端消息，会进入 HTML 属性与 CSS 选择器；只接受 [A-Za-z0-9_-]，
// 其余一律判为异常客户端发来的消息，在接收侧丢弃。
export function isSafeFileId(id) {
	return typeof id === 'string' && id.length > 0 && id.length <= 80 && /^[A-Za-z0-9_-]+$/.test(id);
}

// ---------------------------------------------------------------------------
// 房间口令强度
// ---------------------------------------------------------------------------
//
// 口令在本协议里同时充当唯一的安全预算：它作为 IKM 的一部分参与端到端密钥
// 派生，一旦被离线枚举，冒充服务端的中继就能解出全部内容。临时 ECDH 密钥只能
// 保证「没有口令就拿不到密钥」，不能保证「口令弱也安全」。
//
// 因此这里只做保守的弱口令识别，不做评分、不做阻断。阻断会把用户赶走，而风险
// 由用户自行承担；提示的目的只是让人知道这条路不是靠算法强度兜着的。
// 返回 null 表示无需提示，否则返回文案的 i18n key。

const COMMON_PASSWORDS = [
	'12345678', '123456789', '1234567890', '123456789012',
	'password', 'password1', 'password123', 'passw0rd',
	'qwertyui', 'qwertyuiop', '11111111', '00000000',
	'88888888', '66666666', 'abcd1234', 'iloveyou'
];

export function assessPasswordStrength(password) {
	const value = String(password === null || password === undefined ? '' : password);
	if (value.length === 0) {
		return 'ui.pwd_empty'
	}
	if (value.length >= 12 && !COMMON_PASSWORDS.includes(value.toLowerCase())) {
		return null
	}
	const lower = value.toLowerCase();
	if (COMMON_PASSWORDS.includes(lower)) {
		return 'ui.pwd_weak'
	}
	// 纯数字或纯字母且不足 12 位：枚举空间小到离线爆破不成问题
	if (/^(?:\d+|\D+)$/.test(value) && value.length < 16) {
		return 'ui.pwd_weak'
	}
	if (value.length < 8) {
		return 'ui.pwd_weak'
	}
	return null
}
