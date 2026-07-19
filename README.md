Secret Guard
============

防止你的 Agent 不经意间将你的 Secrets (password, private keys, token, cookies) 泄露到 LLM Provider 服务器上.

---

这是一个超轻量级的 LLM Gateway, 它提供的功能是:

1. 在本地起一个 LLM 网关进程, 你可以将 claude-code / opencode / hermes-agent 等软件的 API BASE URL 指向它监听的本地地址
2. 它将原封不动地转发LLM的输入输出, 同时在本地程序中检查其中是否包含你的 Secret, 并将其替换为 Mock Secret.
3. 它会在收到的LLM响应中(包括工具调用中)进行反向替换, 以使得包含 Secret 的工具调用在你的本地仍然能正常运行. 整个过程只对 LLM 透明.
4. 它会在生成 Mock Secret 时, 确保它在会话中的唯一性, 以使得它完全不可能跟其他内容出现同名撞车, 不用担心响应中的内容被错误地替换.
5. 它会精心生成像模像样的 Mock Secret , 以使得从 LLM 的视角看, 它几乎就是一个真 Secret, 不会被 LLM 质疑这个 Secret 的合法性 (比如 LLM 不会因发现 Mock Secret 很假而错误地提示你 "它的长度太短" 之类的问题, 而引入 LLM 响应噪音)

