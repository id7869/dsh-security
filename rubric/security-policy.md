# 安全审计策略

本文定义 dsh-security 扫描的**审计范围、不审范围、必须保持的安全属性**。inventory / discover / validate 阶段应在审计时读取本文件并遵守。

## 审计范围 (in-scope)

- 仓库内所有源代码文件（源码语言：JavaScript、TypeScript、Python、Go、Java、C#、Rust、PHP 等）
- 配置文件（环境变量模板、数据库迁移脚本、CI 配置、Dockerfile、K8s 清单）
- API 路由/控制器、认证中间件、数据库访问层

## 不审范围 (out-of-scope)

- `node_modules/`、`vendor/`、`target/`、`dist/`、`build/` 等依赖与产物目录
- 测试文件（除非测试本身暴露安全漏洞，如硬编码凭据）
- 文档、changelog、纯数据文件
- 已标注 `// safe: reviewed` 或 `# nosec` 的已知安全代码行

## 安全属性（必须保持）

扫描发现不得引入 new risk 的建议，且不得建议破坏以下属性的修改：

- **认证**：所有非公开端点必须有有效的认证/授权检查。
- **数据完整性**：关键写操作必须有输入校验或参数化查询。
- **机密性**：凭据不得出现在源码或版本历史中。
- **最小权限**：服务账号/API key 的权限应限定在必要范围。

## 风险接受 (accepted-risk)

若某类问题被业务方明确接受，在此列出，discover/validate 将其 disposition 标记为 `suppressed`：

（当前为空，按需填写）
