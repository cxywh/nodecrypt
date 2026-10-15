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

// 校验 fileId 是否符合生成器产出的字符集。
// fileId 来自对端消息，会进入 HTML 属性与 CSS 选择器；只接受 [A-Za-z0-9_-]，
// 其余一律判为异常客户端发来的消息，在接收侧丢弃。
export function isSafeFileId(id) {
	return typeof id === 'string' && id.length > 0 && id.length <= 80 && /^[A-Za-z0-9_-]+$/.test(id);
}
