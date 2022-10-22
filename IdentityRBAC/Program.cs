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
    // ���� Swagger ��֤��Ϣ
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

// Identity���
builder.Services.AddDbContext<IdentityDb>(opt => {
    var connectionString = @"Server=localhost;database=rbactest;uid=root;pwd=1q2wazsx;";
    var serverVersion = new MySqlServerVersion(new Version(8, 0, 27));
    opt.UseMySql(connectionString, serverVersion);
});
// ����Identity�����������õ�
builder.Services.AddDataProtection();
builder.Services.AddIdentityCore<MyUser>(opt => {
    opt.Password.RequireDigit = false; //�����Ƿ�����������
    opt.Password.RequireLowercase = false; //�����Ƿ�������Сд
    opt.Password.RequireNonAlphanumeric = false;  //�����Ƿ�����������ĸ�����ַ�
    opt.Password.RequireUppercase = false; //�����Ƿ���������д
    opt.Password.RequiredLength = 6;  //�����������ﵽ����С���ȡ� Ĭ��Ϊ 6

    // Ĭ���ǳ�������������������Ƕ�����
    opt.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultEmailProvider; //���������������õ����ʼ���ʹ�õ�����
    opt.Tokens.EmailConfirmationTokenProvider = TokenOptions.DefaultEmailProvider; //�ʻ�ȷ�ϵ����ʼ���ʹ�õ�����

});
IdentityBuilder ideBuilder = new IdentityBuilder(typeof(MyUser), typeof(MyRole), builder.Services);
ideBuilder.AddEntityFrameworkStores<IdentityDb>()
    .AddDefaultTokenProviders()
    .AddUserManager<UserManager<MyUser>>()
    .AddRoleManager<RoleManager<MyRole>>();

// ����jwt
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
            //��֤ǩ��
            ValidateIssuerSigningKey = true,
            //����ǩ����֤
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            //��֤�䷢��
            ValidateIssuer = false,
            ValidIssuer = jwtSettings.Issuer,
            //֤����Ⱥ��
            ValidateAudience = false,
            ValidAudience = jwtSettings.Audience,

        };
    });

// �ӻ������
builder.Services.AddMemoryCache();

// ��� Sang RBAC ����
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
// UseAuthentication ֮�� UseAuthorization ֮ǰ
app.UseRolePermission(opt => {
    // ����ϵͳ���ó�������Ա��rolename
    opt.userAdministratorRoleName = "supadmin";
});
app.UseAuthorization();


app.MapControllers();

app.Run();
