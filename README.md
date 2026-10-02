# 深海浮标采集前缀封存服务

岸站服务：浮标经卫星链路回传带 Ed25519 签名的测量摘要，服务在乱序、重传与
进程重启后只封存**一条连续且未分叉**的采集前缀。SQLite 单文件持久化，所有
裁决（记录落库 / 连续水位推进 / 分叉冻结）在同一个 `BEGIN IMMEDIATE`
事务中提交后才返回 HTTP 响应。

## 运行

```bash
# 宿主端口可配置（默认 8080）
HOST_PORT=9000 docker compose up -d --build server
curl -s http://localhost:9000/health

# 一键验证：代码测试 + 镜像构建检查 + HTTP 冒烟（含中途重启），退出码即结果
docker compose build verify
docker compose up --build verify        # 退出 0 表示全部通过
docker compose up verify; echo $?       # 单独再跑一次
```

`verify` 容器依次执行：

1. `pytest tests`：乱序归并、窗口拒绝、分叉冻结（内容冲突 / 签名冲突 /
   封存时前序不匹配）、公钥不可更换、重启重建、12 线程并发；
2. 经挂载的 Docker socket 执行 `docker build -f Dockerfile .`（镜像构建检查）；
3. HTTP 冒烟 phase1（乱序、重传裁决、窗口、分叉冻结）→
   `docker restart buoy-server` → phase2（重启后水位重建与重传、补齐缺口封存）；
4. 全部通过退出码 0，任一步失败立即以非零码退出。

## API

### `POST /streams`

```json
{ "id": "buoy-alpha-7", "public_key": "<base64 的 32 字节 Ed25519 公钥>" }
```

- `id` 为非空 ASCII；`201` 首次创建，`200` 同公钥幂等重放；
- 同一 `id` 换公钥 → `409`，标识一经创建公钥永久绑定。

### `POST /streams/{id}/records`

```json
{
  "seq": 3,
  "prev_digest": "<64 个 hex 字符，32 字节>",
  "payload_digest": "<64 个 hex 字符，32 字节>",
  "signature": "<base64 的 64 字节 Ed25519 签名>"
}
```

响应：

| 情形 | 状态码 | `status` |
|---|---|---|
| 记录在本轮补齐并封存 | 200 | `sealed` |
| 已接收但前方有缺口，进入最多 32 的乱序缓冲 | 200 | `pending` |
| 同序号逐字节相同重传（签名一致） | 200 | 沿用原裁决 + `"retransmit": true` |
| 序号超出 `water_level + 32` | 422 | `out_of_window`（不冻结） |
| 新序号签名验不过 | 400 | `invalid_signature`（不冻结） |
| 同序号内容/签名不同，或封存时 `prev_digest` 与链上摘要不符 | 409 | `forked`（流被原子冻结） |
| 流已冻结后的任何提交 | 409 | `forked` |

每条响应都带当前 `water_level`（已封存连续前缀的最高序号）与 `forked`。

### 签名消息（规定二进制，禁止用 JSON 重编码验签）

签名覆盖且仅覆盖以下字节的大端拼接：

```
uint16 BE 标识字节长度 │ ASCII 标识字节 │ uint64 BE 序号 │ 32B 前序摘要 │ 32B 载荷摘要
```

- 首条记录 `seq=1`，`prev_digest` 必须为 32 字节全零；
- 第 n 条记录的 `prev_digest` 必须等于第 n-1 条封存记录的 `payload_digest`；
- 摘要用 hex 传输、签名/公钥用标准 base64 传输，但验签只针对上述规范字节。

### `GET /streams/{id}` / `GET /health`

查询水位、链尖摘要与冻结标志；健康检查返回 `{"status":"ok"}`。

## 持久化与重启

- `streams` 表保存 `water_level`、`last_digest`、`forked`；`records`
  表保存全部记录（含未封存的乱序缓冲，`sealed` 标志区分）。
- 启动时 `rebuild_water_levels()` 不信任缓存水位，从 `seq=1` 起按
  `sealed` 记录重放并重新校验前序链，重算出相同水位；缓冲记录在
  重启后缺口补齐时照常封存。
- 所有写操作使用 `BEGIN IMMEDIATE` + WAL + `busy_timeout`，并发提交被
  串行化，不会重复封存，也不会出现先成功后冻结的短暂错误成功。

## 本地开发

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests -q
DB_PATH=./data/dev.db PORT=8080 .venv/bin/python wsgi.py
```
