// tests/frontend-r2.test.mjs 用的桩：替换真的 util.fileUpload.js
//
// 真的那个会去建模态框、等用户在界面上点「发送」，测试里没法走完。
// 桩只做一件事：把 setupFileSend 传进来的 onSend 回调存下来，
// 让测试能直接把 File 对象喂进去 —— 于是「点附件 -> 分块加密 -> 发清单」
// 这条真实链路（用的是真的 handleFilesUpload / uploadFilesViaR2）就能被跑到。

let pendingOnSend = null;

export function showFileUploadModal(onSend) {
	pendingOnSend = onSend;
}

/** 测试用：直接喂文件给 UploadModal 的回调 */
export function __feedFiles(files) {
	if (!pendingOnSend) {
		throw new Error('还没有回调 —— 先点一次附件按钮，让 setupFileSend 注册它');
	}
	return pendingOnSend(files);
}

export function __hasCallback() {
	return pendingOnSend !== null;
}
