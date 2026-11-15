"""运营后台访问控制。

复用 auth.verify_token（签名、算法、过期时间），租户只取自已验证的令牌声明。
参见 docs/auth-policy.md 第 2、5 节与 docs/tenant-isolation.md。
"""

import jwt
from fastapi import HTTPException, Request

from .auth import verify_token
from .repository import TenantContext

# 允许访问 /api/ops 的角色。已认证但不在此列的角色一律 403。
OPS_ROLES = frozenset({"ops_admin"})


def require_ops(request: Request) -> TenantContext:
    """校验运营请求并返回认证上下文，用作 /api/ops 端点的依赖。"""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme != "Bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="未认证")
    try:
        claims = verify_token(token.strip())
    except (jwt.InvalidTokenError, KeyError) as invalid:
        # 伪造、过期、算法不符或缺少必需声明，一律按未认证处理
        raise HTTPException(status_code=401, detail="未认证") from invalid
    if claims.role not in OPS_ROLES:
        raise HTTPException(status_code=403, detail="无运营管理权限")
    # 租户只来自已验证的令牌；请求头与查询参数里的租户标识不参与
    return TenantContext(tenant_id=claims.tenant_id, user_id=claims.user_id, role=claims.role)
