using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Sang.AspNetCore.RoleBasedAuthorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace IdentityRBAC.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserManager<MyUser> userManager;
        private readonly RoleManager<MyRole> roleManager;

        private readonly ILogger<UserController> _logger;

        public UserController(ILogger<UserController> logger, UserManager<MyUser> userManager, RoleManager<MyRole> roleManager)
        {
            _logger = logger;
            this.userManager = userManager;
            this.roleManager = roleManager;
        }

        /// <summary>
        /// 创建初始用户
        /// </summary>
        /// <returns></returns>
        [HttpGet("init")]
        public async Task<IActionResult> Index()
        {
            // 添加角色 和 用户
            string[] makerole = { "admin","supadmin","user" };

            foreach(var rolename in makerole)
            {
                if (!await roleManager.RoleExistsAsync(rolename))
                {
                    MyRole role = new MyRole { Name = rolename };
                    var res = await roleManager.CreateAsync(role);
                    if (!res.Succeeded) return BadRequest(res.ToString());

                    if (rolename == "admin")
                    {
                        await roleManager.AddClaimAsync(role, new Claim(ResourceClaimTypes.Permission, "增加"));
                        await roleManager.AddClaimAsync(role, new Claim(ResourceClaimTypes.Permission, "查询"));
                    }else if(rolename == "user")
                    {
                        await roleManager.AddClaimAsync(role, new Claim(ResourceClaimTypes.Permission, "查询"));
                    }
                }
                // 添加用户
                MyUser user = await userManager.FindByNameAsync(rolename);
                if (user is null)
                {
                    user = new MyUser { UserName = rolename, Email = $"{rolename}@qq.com", EmailConfirmed = true };
                    var res = await userManager.CreateAsync(user, "123456");
                    if (!res.Succeeded) return BadRequest(res.ToString());
                }

                if (!await userManager.IsInRoleAsync(user, rolename))
                {
                    var res = await userManager.AddToRoleAsync(user, rolename);
                    if (!res.Succeeded) return BadRequest(res.ToString());
                }
            }

            return Ok("ok");
        }

        /// <summary>
        /// 检查用户密码
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost("check")]
        public async Task<IActionResult> CheckPassword(CheckPwdRequest req)
        {
            string userName = req.userName;
            string pwd = req.Password;
            var user = await userManager.FindByNameAsync(userName);
            if (user is null)
            {
                return BadRequest("初始化用户有admin、supadmin、user");
            }

            if (await userManager.IsLockedOutAsync(user))
            {
                return BadRequest("用户锁定，结束时间" + user.LockoutEnd);
            }
            if (await userManager.CheckPasswordAsync(user, pwd))
            {
                // 恢复失败次数
                await userManager.ResetAccessFailedCountAsync(user);


                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("You_JWT_Secret_Key"));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                        new Claim(ClaimTypes.Name,userName),
                        new Claim(ClaimTypes.Email,user.Email)
                    };
                // 循环查询所有角色
                var roles = await userManager.GetRolesAsync(user);
                foreach (string role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                var token = new JwtSecurityToken(
                    "Issuer",
                    "Audience",
                    claims,
                    expires: DateTime.UtcNow.AddSeconds(3600),
                    signingCredentials: credentials
                );
                return Ok(new
                {
                    access_token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }

            await userManager.AccessFailedAsync(user);
            return BadRequest("登录失败");

        }

        /// <summary>
        /// 全部权限列表
        /// </summary>
        /// <returns></returns>
        [HttpGet("Resources")]
        public IActionResult Resources()
        {
            return Ok(ResourceData.Resources);
        }

        public record CheckPwdRequest(string userName, string Password);
    }
}