using IdentityRBAC;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Sang.AspNetCore.RoleBasedAuthorization;
using Sang.AspNetCore.RoleBasedAuthorization.RolePermission;
using System.Reflection;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => {
    // 配置 Swagger 认证信息
    options.AddSecurityDefinition("bearerAuth", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "JWT Authorization header using the Bearer scheme."
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "bearerAuth" }
            },
            new string[] {}
        }
    });
    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var filePath = Path.Combine(AppContext.BaseDirectory, xmlFilename);
    options.IncludeXmlComments(filePath);
});

// Identity框架
builder.Services.AddDbContext<IdentityDb>(opt => {
    var connectionString = @"Server=localhost;database=rbactest;uid=root;pwd=1q2wazsx;";
    var serverVersion = new MySqlServerVersion(new Version(8, 0, 27));
    opt.UseMySql(connectionString, serverVersion);
});
// 用于Identity框架密码加密用的
builder.Services.AddDataProtection();
builder.Services.AddIdentityCore<MyUser>(opt => {
    opt.Password.RequireDigit = false; //密码是否必须包含数字
    opt.Password.RequireLowercase = false; //密码是否必须包含小写
    opt.Password.RequireNonAlphanumeric = false;  //密码是否必须包含非字母数字字符
    opt.Password.RequireUppercase = false; //密码是否必须包含大写
    opt.Password.RequiredLength = 6;  //设置密码必须达到的最小长度。 默认为 6

    // 默认是超长参数，配置下面后是短数字
    opt.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider; //用于生成密码重置电子邮件中使用的令牌
    opt.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider; //帐户确认电子邮件中使用的令牌

});
IdentityBuilder ideBuilder = new IdentityBuilder(typeof(MyUser), typeof(MyRole), builder.Services);
ideBuilder.AddEntityFrameworkStores<IdentityDb>()
    .AddDefaultTokenProviders()
    .AddUserManager<UserManager<MyUser>>()
    .AddRoleManager<RoleManager<MyRole>>();

// 配置jwt
JWTSettings jwtSettings = new()
{
    SecretKey = "You_JWT_Secret_Key",
    ExpireSeconds = 3600
};
builder.Services.Configure<JWTSettings>(opt => {
    opt.SecretKey = jwtSettings.SecretKey;
    opt.ExpireSeconds = jwtSettings.ExpireSeconds;
});
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(opt => {
        opt.TokenValidationParameters = new()
        {
            //验证签名
            ValidateIssuerSigningKey = true,
            //用于签名验证
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            //验证颁发者
            ValidateIssuer = false,
            ValidIssuer = jwtSettings.Issuer,
            //证访问群体
            ValidateAudience = false,
            ValidAudience = jwtSettings.Audience,

        };
    });

// 加缓存服务
builder.Services.AddMemoryCache();

// 添加 Sang RBAC 服务
builder.Services.AddSangRoleBasedAuthorization();
builder.Services.AddRolePermission<MyRolePermission>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();


app.UseAuthentication();
// UseAuthentication 之后 UseAuthorization 之前
app.UseRolePermission(opt => {
    // 设置系统内置超级管理员的rolename
    opt.userAdministratorRoleName = "supadmin";
});
app.UseAuthorization();


app.MapControllers();

app.Run();
