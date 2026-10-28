# RJMoonTv 1.0.1 修复说明

基于 `main` HEAD `1fb6fe4`（2026-10-28 审计快照）。只改下面列出的文件，
不改数据库结构，不改任何上游源地址本身（只改本仓的引用）。

## 版本

- 你说的“原版本 1.0.0 → 1.0.1”在本仓没有对应的字段：本仓实际显示版本
  是 `src/lib/version.ts` 的 `100.1.3`、`VERSION.txt` 的 `100.1.3`、
  `package.json` 的 `0.1.0`。按你的要求统一改为 `1.0.1`：
  `src/lib/version.ts`、`VERSION.txt`、`package.json` 均为 `1.0.1`。
- 版本检查 `src/lib/version_check.ts` 原来指向 `MoonTechLab/LunaTV`，
  且备用 URL `VERSION_CHECK_URLS[1]` 根本不存在（会取 undefined）。
  已改为只查本仓 `xinyule/RJMoonTv/main/VERSION.txt`，并修掉备用 URL 的越界取值。
  这样改到 1.0.1 后不会再因为上游是 100.x 而永远提示“有更新”。

## P0 修复

### 1. 直播代理 SSRF（m3u8 / segment / key / logo / live/precheck）
- `src/lib/proxy-guard.ts` 重写：只允许 http/https；字面内网、
  DNS 解析到内网、重定向目标内网，逐跳拦截；重定向不再用 `redirect:'follow'`，
  改为手动跟随并每跳重验（`fetchValidated`）。
- 上述 5 个接口全部改走 `fetchValidated`，并补上此前缺失的守卫：
  台标接口此前连目标地址限制都没有。
- 默认不放行内网。局域网 IPTV 确实需要内网代理时，由部署者显式设置
  `PROXY_ALLOW_PRIVATE=true` 并自行承担 SSRF 风险；图片代理永远不放行内网。
- 短请求（m3u8/key/logo/precheck/图片）加 15 秒超时；segment 流式传输不设总超时，
  否则长视频会被中途掐断。
- 剩余风险（已说明，不算修完）：已登录用户仍可用服务器代理任意**公网**地址，
  这是直播代理本身的设计，改“只代理本源地址”会断掉 CDN 分片，暂未做。

### 2. 会话永不失效（改密/封禁/删号后旧 Cookie 仍可用）
- 新增 `src/lib/user-guard.ts`：
  - 数据库模式 Cookie 签名改为 `HMAC(username:sessionEpoch, PASSWORD)`；
  - 登录时签发/沿用会话纪元 `sessionEpoch` 并落盘到配置用户条目
    （`src/lib/admin.types.ts` 新增 `sessionEpoch` 字段，`configSelfCheck`
    保留站长的纪元）；
  - API 层校验：用户不存在、被封禁、无纪元、纪元与配置不一致，一律 401。
- `src/middleware.ts`：补上此前只发不验的 Cookie 时间戳校验（超过 7 天失效，
  未来超过 5 分钟也失效）；数据库模式要求带纪元，旧 Cookie 直接失效；
  localstorage 模式改为只认密码 SHA-256 摘要，不再认明文密码。
- `src/app/api/login/route.ts`：登录签发纪元；localstorage 模式 Cookie 里
  只放密码摘要，不再放明文密码；登录加内存限流（同一 IP 5 分钟内失败
  20 次后返回 429），缓解弱口令爆破和 scrypt CPU 消耗。
- 改密/封禁/降级轮换纪元：
  - 自助改密（`change-password`）改密后轮换纪元并清当前 Cookie，强制重新登录；
  - 后台用户管理（`admin/user`）的封禁、改密、取消管理员均轮换目标用户纪元；
  - 删号直接从配置移除用户，API 层即拦。
- 应用范围：搜索、详情、搜索子接口、直播频道/节目单/源/预检、代理、
  图片代理、豆瓣、番剧、收藏/播放记录/搜索历史/跳过配置、全部后台接口，
  均已接入 `getActiveUser`。中间件本身读不到数据库，所以封禁/纪元校验
  只能在 API 层做，页面外壳仍可能加载，但数据接口会 401 并跳回登录页。
- **升级后所有用户必须重新登录一次**（旧 Cookie 无纪元、无摘要，必然失效），
  这是故意的，不是回归。

### 3. 无鉴权 cron
- `src/app/api/cron/route.ts`：此前任何人都能触发“刷新全部直播源、遍历全部
  用户播放记录/收藏并请求上游”。现要求 `CRON_SECRET`：
  请求头 `Authorization: Bearer <secret>` 或 `x-cron-secret: <secret>`，
  用等长比较；不配 `CRON_SECRET` 时 cron 直接返回 401，不再默认公开。
- `start.js`：Docker 内部定时任务已改为在配了 `CRON_SECRET` 时用请求头转发。
  Vercel Cron 在项目里配了 `CRON_SECRET` 后会自动带 Bearer token。
  **部署时务必配 `CRON_SECRET`，否则定时刷新会停掉**（播放本身不受影响）。

### 4. GET 改配置（CSRF）
- `src/app/api/admin/reset/route.ts`：重置配置由 GET 改为 POST，GET 返回 405；
  `src/app/admin/page.tsx` 同步改为 POST。站长访问任意页面/图片不再能触发重置。

### 5. 备份导出含站长明文密码
- `src/app/api/admin/data_migration/export/route.ts`：
  - 删除把 `process.env.PASSWORD` 明文写进备份的那一行，站长密码字段改为 null；
    恢复后站长仍用环境变量里的密码登录，导入时 `if (user.password)` 会跳过该字段；
  - 备份加密口令要求至少 12 位（此前无长度要求，口令弱等于没加密）。
  - 其他用户的密码仍是库里存的哈希（迁移后）或旧明文（未迁移的旧账号），
    备份文件本身仍属敏感文件，口令请用随机长口令，勿公开存放。
  - 导入前已做结构校验才清库，但导入中途失败仍无事务回滚：
    **导入前请先自己备份一次**，这是原有设计，本次未改存储层。

## 其他修复

- 密码强度：自助改密、后台新增用户、后台改密，均改为至少 8 位且同时含
  字母和数字（此前自助改密只要求去空格后不少于 6 位，后台新增只校验非空）。
- 安全响应头：`next.config.js` 增加 `X-Content-Type-Options: nosniff`、
  `X-Frame-Options: SAMEORIGIN`、`Referrer-Policy`、`Permissions-Policy`
 （未加严格 CSP，Next 内联脚本会因此被拦，暂不做）。
- `proxy.worker.js`：该文件是独立的开放代理，Next 主应用不用它。
  本次只在文件头加了“请勿公开部署、须放在鉴权后面”的警告，未改其功能；
  公开部署它本身就是开放代理，靠改代码也拦不住设计意图。
- 同步上游工作流：`sync-upstream.yml` 的推送目标由 `xinyule/Moontv-lunatv`
  改为 `xinyule/RJMoonTv`（此前在 RJMoonTv 仓里跑却推向另一个仓）。
  **注意：该工作流的 force 模式会丢弃本地提交（含本次 1.0.1），同步时请用 merge 模式，
  或先确认再跑。**

## 仓库引用（Dockerfile / 说明 / 配置）

- `Dockerfile`：它本来就不 clone 任何仓库（本地 COPY 构建），不存在“默认仓库”
  是别人的问题；已在文件头注明本仓 `xinyule/RJMoonTv`，镜像名见工作流。
- `.github/workflows/docker-image.yml`：镜像由 `ghcr.io/moontechlab/lunatv`
  改为 `ghcr.io/xinyule/rjmoontv`（GHCR 要求小写）。
- `README.md`：4 处部署镜像改为 `ghcr.io/xinyule/rjmoontv:latest`，
  Star 图由 `MoonTechLab/LunaTV` 改为 `xinyule/RJMoonTv`。
- 刻意未改：`sync-upstream.yml` 里 `MoonTechLab/LunaTV` 作为同步**来源**是
  正确的，改了就同步不到上游；README 里对 LunaTV / Selene / OrionTV 等
  第三方项目的致谢和功能描述不是本仓引用，不动。

## 回滚

- 本次只改代码文件，无数据库迁移。回滚方法见随包的
  `RJMoonTv-1.0.0-rollback.zip`（同批文件的原版，版本仍是原值）：
  - 未合并 PR 前：直接关掉 PR，`main` 仍是原 `1fb6fe4`，什么都不用做；
  - 已合并后：`git revert <合并提交>`，或 `git reset --hard 1fb6fe4`；
  - 已部署到服务器：把回滚包按目录覆盖回站点根目录并重启。
- 回滚后用户需要重新登录一次（新旧 Cookie 格式不同，互不兼容）。
- 回滚不会自动撤销“改密后轮换的纪元”：已轮换的用户在回滚后仍可用旧 Cookie
  登录（因为回滚版不验纪元），如需彻底作废，请在回滚后让相关用户改密或重新登录。

## 本次未做、需你另外确认的

- 上线前请在非生产环境实测：登录、搜索、播放、直播、豆瓣图片、后台改密/封禁
  后旧 Cookie 是否失效、cron 配了 secret 后是否正常触发。
- 局域网 IPTV 若代理内网地址，请配 `PROXY_ALLOW_PRIVATE=true`，否则内网直播
  会被新校验拦住（这是安全默认值，不是 bug）。
- 未做动态验证：本次检查是静态/文件比对 + 语法检查，未跑生产站、未连真实数据库。
