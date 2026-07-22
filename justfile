# secret-guard — justfile
# 一键命令集合, 覆盖开发 / 检查 / 测试 / 运行.

default:
    @just --list

# 进入 nix devShell (交互式).
shell:
    nix develop --impure

# 编译.
build:
    cargo build

# 编译并运行.
run *ARGS:
    cargo run -- {{ARGS}}

# 开发模式: 自动重编译 (cargo-watch).
dev:
    cargo watch -x 'run -- run'

# 一次跑完: fmt + clippy + machete (unused deps) + test.
check:
    cargo fmt -- --check
    cargo clippy --all-targets -- -D warnings
    cargo machete
    cargo nextest run --no-fail-fast
    cargo test --doc

# WebUI 回归测试 (Playwright 端到端).
# 需要 devShell (nix develop) 提供 playwright-test 包; shellHook 自动 symlink node_modules.
check-webui:
    cd tests/webui && playwright test

# check + check-webui (完整验证, devShell 内).
check-all: check
    cd tests/webui && playwright test

# 仅 fmt.
fmt:
    cargo fmt

# 仅 clippy.
clippy:
    cargo clippy --all-targets -- -D warnings

# 仅 test.
test:
    cargo nextest run --no-fail-fast

# 启动 mock 上游 (用于本地集成测试; 占位).
mock-upstream:
    @echo "TODO: 第二步会引入 mockito-based 上游"

# 检查依赖漏洞.
audit:
    cargo audit
