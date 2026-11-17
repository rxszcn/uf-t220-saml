# 交付说明：按 SP 请求驱动的 IdP 属性发布（t220）

## 背景与问题

集团 SP 门户在元数据 `AttributeConsumingService` 中按 `RequestedAttribute`
请求 `employeeNumber`（`urn:oid:2.16.840.1.113730.3.1.3`）与 URI 格式的
`emailAddress`，但断言中一个都拿不到；而不声明任何请求属性的测试 SP 反而
收到全集。根因在 `DefaultAssertionMaker.MakeAssertion`：

- 请求通道只识别五组硬编码的 basic 普通属性名（email / name / givenName /
  surname / uid），且仅处理 `basic`、`unspecified`、空三种 `NameFormat`；
- 任何 URI 格式（OID、claim URI 等）或五组之外的普通名，`switch` 无分支
  命中，被**静默丢弃**；
- 随后无条件把 `Session` 能产出的全部属性追加进断言，于是"什么都不请求"
  的 SP 拿到全集。请求通道实际上无法驱动发布，最小化发布无法通过合规审查。

## 改动清单

| 文件 | 改动 |
| --- | --- |
| `identity_provider_attributes.go`（新增） | 属性发布全部逻辑：ACS 选择、请求属性解析、精确名匹配、session 全量属性构造、去重、开关判断 |
| `identity_provider.go` | 新增 `IdentityProvider.ReleaseRequestedAttributesOnly` 开关；`MakeAssertion` 属性段改为调用新逻辑；移除已不再直接使用的 `attrname` 导入 |
| `identity_provider_attribute_release_test.go`（新增） | 三组验收断言及边界用例 |
| `README.md` | IdP 章节新增 "Releasing attributes" 小节 |

## 发布行为设计

### 1. 请求属性一律按名响应，不再静默丢弃

对 SP 请求的每个 `RequestedAttribute`：

- **五组历史 basic 名**：保留原有"去标点、大小写敏感"的匹配与空值应答
  行为（`TestIDPRequestedAttributes`、golden 文件依赖，不变）；
- **五组之外的任意名称**（含 URI 格式 OID、非常规普通名）：在 session
  全量属性中按 `Name` 做**精确、大小写敏感**的二进制比较
  （saml-core §1.3.1），命中即按 SP 请求的 `Name`/`NameFormat`/`FriendlyName`
  发布。非常规属性通过 `Session.CustomAttributes` 供给；
- **NameFormat 规则**：请求显式给出 `NameFormat` 时要求格式一致；请求
  不带 `NameFormat`（即 unspecified，saml-core §2.7.3.1）时可匹配任意
  格式的同名属性，与 `x/samlidp.FilterAttributes` 的既有语义一致；
- **无法满足的请求**：不伪造数据，直接省略该属性。五组历史 basic 名
  例外，维持历史的空值应答；
- 以 `NameFormat + Name` 为键去重，重复请求不产生重复属性。

不使用 `FriendlyName` 参与属性识别——saml-core §2.7.3.1 明确规定
FriendlyName "MUST NOT be used as a basis for formally identifying SAML
attributes"，且 `TestSpecCore_2_7_3_1_GetByNameIgnoresFriendlyName`
已固定这一立场。

### 2. 未请求属性的发布策略与兼容性取舍（自行决策部分）

引入**显式开关、默认关闭**的 `IdentityProvider.ReleaseRequestedAttributesOnly`，
而非直接改变默认行为，理由：

1. **向后兼容是硬约束**。现有断言（`TestIDPMakeAssertion` 对属性顺序与
   全集的 `DeepEqual`、`TestIDPCanHandleUnencryptedResponse` 的 golden
   签名文件、`x/samlidp` 及大量下游用例）都固定了"请求之外再发全集"的
   旧行为，默认翻转会立即破坏既有 SP，尤其是依赖未在元数据中声明的
   `uid`/`mail`/`eduPersonPrincipalName` 等属性的存量集成；
2. 与库内既有设计一致。`x/samlidp` 已采用同名 opt-in 选项
   `ReleaseRequestedAttributesOnly()`，根包开关命名与语义与其对齐，
   应用在两层之间迁移时认知成本最低；
3. 合规要求由开关满足。开启后：
   - 只发布被请求且 session 能提供的属性，按请求顺序输出；
   - SP 未声明任何 `RequestedAttribute`（或没有
     `AttributeConsumingService`）时，**不发布任何属性**，空
     `AttributeStatement` 仍保留；
   - 请求的 `AttributeConsumingServiceIndex` 在 SP 元数据中不存在时，
     返回 `Requester` / `RequestUnsupported` 的 `*StatusError`（经
     `ServeSSO` 成为 SAML 错误 Response），而不是静默回退默认服务。
     该严格校验只在开关开启时生效——关闭时维持历史行为（忽略 index、
     用默认服务），这是 `x/samlidp` 测试固定的兼容行为。

### 3. 不做的事

- 不依据 `isRequired` 让断言失败：如何处理缺失的必备属性属于应用策略
  （`x/samlidp.MissingRequiredAttributes` 已提供检查工具），默认 maker
  保持"能发则发、不能发则省略"；
- 不按 `RequestedAttribute` 内嵌的 `AttributeValue` 过滤值：根包
  `Session` 模型没有对应的值级同意机制，保持简单；
- 不改变五组 basic 名的空值应答这一历史行为。

## 新增测试（`identity_provider_attribute_release_test.go`）

三组验收断言，均以既有 email 场景作正对照：

1. `TestIDPAttributeReleaseDrivenByRequest` —— **请求发布**：basic 格式
   非常规名 `departmentNumber`（五组之外）经 `CustomAttributes` 精确命中；
   同用例内 basic `email` 为正对照；
2. `TestIDPAttributeReleaseURIFormatOID` —— **OID/URI 请求**：
   `attrname.EmployeeNumber` 与 `attrname.Mail` 两个 URI 格式请求均正确
   发布（修复前两者都会被静默丢弃），mail 为正对照；
3. `TestIDPAttributeReleaseMinimization` —— **最小化行为**：开关开启时
   只发可满足的请求属性、不可满足的省略、无请求则零属性；开关关闭时
   保持全集发布的历史行为。

另含边界用例：未知 ACS index 报错、未知名省略、unspecified 格式匹配
任意格式、重复请求去重。

## 验收

- `go test ./...` 全仓库零失败（含 `samlidp`、`x/samlidp`、`x/samlsp`
  等全部子模块）；
- `go vet ./...` 无告警；改动文件 `gofmt` 干净；
- 既有测试（含 `TestIDPRequestedAttributes`、golden 签名文件、
  `TestDefaultAssertionMakerRequestedAttributeNames`、
  `x/samlidp.TestRequestedAttributesUnknownIndex`）全部保持通过，未做
  任何修改。
