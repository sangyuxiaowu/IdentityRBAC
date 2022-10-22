using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Sang.AspNetCore.RoleBasedAuthorization.RolePermission;
using System.Collections.Generic;
using System.Security.Claims;
using System.Xml.Linq;

internal class MyRolePermission : IRolePermission
{

    private readonly IMemoryCache _memoryCache;

    private readonly RoleManager<MyRole> _roleManager;

    private readonly string cachekey = "Role_Permission_";

    public MyRolePermission(IMemoryCache memoryCache, IServiceProvider _sp)
    {
        _memoryCache = memoryCache;
        _roleManager = _sp.CreateScope().ServiceProvider.GetRequiredService<RoleManager<MyRole>>();
    }

    public async Task<List<Claim>> GetRolePermissionClaimsByName(string roleName)
    {
        var claims = await _memoryCache.GetOrCreateAsync(cachekey + roleName, async (e) =>
        {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(3600);
            e.SlidingExpiration = TimeSpan.FromMinutes(10);//10分钟滑动过期
            var myrole = await _roleManager.FindByNameAsync(roleName);
            if (myrole is null) return new List<Claim>();
            var list = await _roleManager.GetClaimsAsync(myrole);
            return list;
        });
        return claims.ToList();
    }
}