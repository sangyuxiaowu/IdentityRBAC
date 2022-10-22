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
        /// ������ʼ�û�
        /// </summary>
        /// <returns></returns>
        [HttpGet("init")]
        public async Task<IActionResult> Index()
        {
            // ��ӽ�ɫ �� �û�
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
                        await roleManager.AddClaimAsync(role, new Claim(ResourceClaimTypes.Permission, "����"));
                        await roleManager.AddClaimAsync(role, new Claim(ResourceClaimTypes.Permission, "��ѯ"));
                    }else if(rolename == "user")
                    {
                        await roleManager.AddClaimAsync(role, new Claim(ResourceClaimTypes.Permission, "��ѯ"));
                    }
                }
                // ����û�
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
        /// ����û�����
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
                return BadRequest("��ʼ���û���admin��supadmin��user");
            }

            if (await userManager.IsLockedOutAsync(user))
            {
                return BadRequest("�û�����������ʱ��" + user.LockoutEnd);
            }
            if (await userManager.CheckPasswordAsync(user, pwd))
            {
                // �ָ�ʧ�ܴ���
                await userManager.ResetAccessFailedCountAsync(user);


                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("You_JWT_Secret_Key"));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                        new Claim(ClaimTypes.Name,userName),
                        new Claim(ClaimTypes.Email,user.Email)
                    };
                // ѭ����ѯ���н�ɫ
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
            return BadRequest("��¼ʧ��");

        }

        /// <summary>
        /// ȫ��Ȩ���б�
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