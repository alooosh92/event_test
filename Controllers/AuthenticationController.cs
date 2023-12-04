using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Net.Mail;
using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using event_test.Data;

namespace jwt
{
    //Controller
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthServies _authServies;
        public AuthenticationController(IAuthServies authServies)
        {
            _authServies = authServies;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<ActionResult<AuthModel>> Register([FromBody] UserModel userModel)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.Register(userModel);
        }
        [HttpPost]
        [Route("RegisterEmployee")]
        [Authorize (AuthenticationSchemes = "Bearer", Roles ="Admin")]
        public async Task<ActionResult<AuthModel>> RegisterEmployee([FromBody] UserModel userModel)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.RegisterEmployee(userModel);
        }
        [HttpPost]
        [Route("Login")]
        public async Task<ActionResult<AuthModel>> Login([FromBody] UserLoginModel userModel)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.Login(userModel);
        }
        [HttpPost]
        [Route("ChangePassword")]
        public async Task<ActionResult<AuthModel>> ChangePassword([FromBody] UserModelPassword userModel)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.ChangePassword(userModel);
        }
        [HttpPost]
        [Route("ForgetPassword")]
        public async Task<ActionResult<bool>> ForgetPassword([FromBody] string username)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);
            return await _authServies.ForgetPassword(username);
        }
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<ActionResult<AuthModel>> RefreshToken([FromBody] string refToken)
        {
            return await _authServies.RefreshToken(refToken);
        }
        [HttpPost]
        [Route("RevokeToken")]
        public async Task<bool> RevokeToken([FromBody] string token)
        {
            return await _authServies.RevokeToken(token);
        }
        [HttpGet]
        [Route("CheckToken")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public bool CheckToken()
        {
            return true;
        }
    }
    
    //Models
    public class AuthModel
    {
        public string? Message { get; set; }
        public bool IsAuthanticated { get; set; }
        public string? Email { get; set; }
        public IList<string>? Roles { get; set; }
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpireson { get; set; }
    }
    public class UserModel
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        public string? Username { get; set; }
        [Required]
        [MinLength(6)]
        public string? Password { get; set; }
    }
    public class UserLoginModel
    {
        [Required]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        [MinLength(6)]
        public string? Password { get; set; }
    }
    public class UserModelPassword
    {
        [Required]
        [EmailAddress]
        public string? UserName { get; set; }
        [Required]
        [MinLength(6)]
        public string? OldPassword { get; set; }
        [Required]
        [MinLength(6)]
        public string? NewPassword { get; set; }
    }
    public class RefreshToken
    {
        [Key]
        public string? Id { get; set; }
        [Required]
        public string? UserId { get; set; }
        [Required]
        public string? Token { get; set; }
        [Required]
        public DateTime? Expirson { get; set; }
        [Required]
        public DateTime? CreatedOn { get; set; }
        [AllowNull]
        public DateTime? RevokedON { get; set; }
    }
    public class JWTValues
    {
        public string? Key { get; set; }
        public string? Issuer { get; set; }
        public string? Audience { get; set; }
        public double DurationInDays { get; set; }
    }

    //Interface
    public interface IAuthServies
    {
        Task<ActionResult<AuthModel>> Register(UserModel userModel);
        Task<ActionResult<AuthModel>> RegisterEmployee(UserModel userModel);
        Task<ActionResult<AuthModel>> Login(UserLoginModel userModel);
        Task<ActionResult<bool>> ForgetPassword(string username);
        Task<ActionResult<AuthModel>> ChangePassword(UserModelPassword userModel);
        Task<ActionResult<AuthModel>> RefreshToken(string token);
        Task<bool> RevokeToken(string token);
    }

    //EmailSender
    public class EmailSender : IEmailSender
    {
        private string host;
        private int port;
        private bool enableSSL;
        private string userName;
        private string password;
        public EmailSender(string host, int port, bool enableSSL, string userName, string password)
        {
            this.host = host;
            this.port = port;
            this.enableSSL = enableSSL;
            this.userName = userName;
            this.password = password;
        }
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var client = new SmtpClient(host, port)
            {
                Credentials = new NetworkCredential(userName, password),
                EnableSsl = enableSSL
            };
            return client.SendMailAsync(
                new MailMessage(userName, email, subject, htmlMessage) { IsBodyHtml = true }
            );
        }
    }

    //AuthServies
    public class AuthServies : IAuthServies
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IOptions<JWTValues> _jwt;
        private readonly IEmailSender _emailSender;
        private readonly ApplicationDbContext _db;
        public AuthServies(UserManager<IdentityUser> userManager, IOptions<JWTValues> jwt, IEmailSender emailSender, ApplicationDbContext db)
        {
            _userManager = userManager;
            _jwt = jwt;
            _emailSender = emailSender;
            _db = db;
        }
        private async Task<JwtSecurityToken> CreateJwtSecurityToken(IdentityUser identityUser)
        {
            var userClaims = await _userManager.GetClaimsAsync(identityUser);
            var roles = await _userManager.GetRolesAsync(identityUser);
            var roleClaims = new List<Claim>();
            foreach (var role in roles)
            {
                roleClaims.Add(new Claim("roles", role));
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,identityUser.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim("uid",identityUser.Id)
            }.Union(userClaims).Union(roleClaims);
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Value.Key!));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Value.Issuer,
                audience: _jwt.Value.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.Value.DurationInDays).ToLocalTime(),
                signingCredentials: signingCredentials);
            return jwtSecurityToken;
        }
        private RefreshToken GeneraterRefreshToken(string userId)
        {
            var randomNumber = new byte[32];
            using var genertor = new RNGCryptoServiceProvider();
            genertor.GetBytes(randomNumber);
            return new RefreshToken
            {
                UserId = userId,
                CreatedOn = DateTime.UtcNow,
                Expirson = DateTime.UtcNow.AddDays(1),
                Id = Guid.NewGuid().ToString(),
                Token = Convert.ToBase64String(randomNumber),
            };
        }
        public async Task<ActionResult<AuthModel>> Register(UserModel userModel)
        {
            if (userModel.Email == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var u = await _userManager.FindByEmailAsync(userModel.Email!);
            if (u is not null) { return new AuthModel { Message = "The email is uses" }; }
            var user = new IdentityUser
            {
                UserName = userModel.Username!,
                Email = userModel.Email!,
                EmailConfirmed = true
            };
            var res = await _userManager.CreateAsync(user, userModel.Password!);
            if (!res.Succeeded) { return new AuthModel { Message = "Error" }; }
            var newUser = await _userManager.FindByEmailAsync(user.Email);
            var refreshToken = GeneraterRefreshToken(newUser!.Id);
            object value = await _db.RefreshTokens.AddAsync(refreshToken);
            if (!res.Succeeded) { return new AuthModel { Message = "Error in Create User" }; }
            await _userManager.AddToRoleAsync(user, "User");
            var token = await CreateJwtSecurityToken(user);
            await _userManager.UpdateAsync(user);
            var back = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.Email!,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpireson = refreshToken.Expirson
            };
            return back;
        }
        public async Task<ActionResult<AuthModel>> Login(UserLoginModel userModel)
        {
            if (userModel.Email == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var user = await _userManager.FindByEmailAsync(userModel.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, userModel.Password)) { return new AuthModel { Message = "username or password is Wrong" }; }
            var token = await CreateJwtSecurityToken(user);
            RefreshToken oldRefreshToken = _db.RefreshTokens.SingleOrDefault(r => r.UserId == user.Id && r.RevokedON == null && DateTime.UtcNow >= r.Expirson)!;
            if (oldRefreshToken != null)
            {
                await RevokeToken(oldRefreshToken.Token!);
            }
            var refreshToken = GeneraterRefreshToken(user.Id);
            _db.RefreshTokens!.Add(refreshToken);
            _db.SaveChanges();
            var rutToken = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.Email,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpireson = refreshToken.Expirson
            };
            return rutToken;
        }
        public async Task<ActionResult<AuthModel>> ChangePassword(UserModelPassword userModel)
        {
            var user = await _userManager.FindByNameAsync(userModel.UserName!);
            if (user == null) return new AuthModel { Message = "Error" };
            var res = await _userManager.ChangePasswordAsync(user,
                userModel.OldPassword!, userModel.NewPassword!);
            if (!res.Succeeded) return new AuthModel { Message = "something is Error" };
            return await Login(new UserLoginModel { Email = userModel.UserName, Password = userModel.NewPassword });
        }
        public async Task<ActionResult<bool>> ForgetPassword(string username)
        {
            if (username == null) return false;
            var user = await _userManager.FindByEmailAsync(username);
            if (user == null) return false;
            var newPass = Guid.NewGuid().ToString().Substring(0, 8);
            var rest = await _userManager.ResetPasswordAsync(user, await _userManager.GeneratePasswordResetTokenAsync(user), newPass);
            if (rest.Succeeded) await _emailSender.SendEmailAsync(username!, "Rest password", $"كلمة السر الجديدة: {newPass}");
            return true;
        }
        public async Task<ActionResult<AuthModel>> RefreshToken(string token)
        {
            var authModel = new AuthModel();
            var tok = await _db.RefreshTokens.SingleOrDefaultAsync(r => r.Token == token);
            if (tok == null)
            {
                authModel.Message = "InValid token";
                return authModel;
            }
            if (!(tok.RevokedON == null && DateTime.UtcNow <= tok.Expirson))
            {
                authModel.Message = "Inactive token";
                return authModel;
            }
            tok.RevokedON = DateTime.UtcNow;
            var newRefreshToken = GeneraterRefreshToken(tok.UserId!);
            await _db.RefreshTokens!.AddAsync(newRefreshToken);
            _db.RefreshTokens.Update(tok);
            await _db.SaveChangesAsync();
            var user = await _userManager.FindByIdAsync(tok.UserId!);
            var jwtToken = await CreateJwtSecurityToken(user!);
            authModel.Message = "Every thing is ok";
            authModel.IsAuthanticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
            authModel.Email = user!.Email;
            var roles = await _userManager.GetRolesAsync(user);
            authModel.Roles = roles.ToList();
            authModel.RefreshToken = newRefreshToken.Token;
            authModel.RefreshTokenExpireson = newRefreshToken.Expirson;
            return authModel;
        }
        public async Task<bool> RevokeToken(string token)
        {
            var toke = await _db.RefreshTokens.SingleOrDefaultAsync(t => t.Token == token);
            if (toke == null) return false;
            if (!(toke.RevokedON == null && DateTime.UtcNow <= toke.Expirson)) return false;
            toke.RevokedON = DateTime.UtcNow;
            _db.RefreshTokens.Update(toke);
            await _db.SaveChangesAsync();
            return true;
        }
        public async Task<ActionResult<AuthModel>> RegisterEmployee(UserModel userModel)
        {
            if (userModel.Email == null || userModel.Password == null) { return new AuthModel { Message = "username or password is null" }; }
            var u = await _userManager.FindByEmailAsync(userModel.Email!);
            if (u is not null) { return new AuthModel { Message = "The email is uses" }; }
            var user = new IdentityUser
            {
                UserName = userModel.Username!,
                Email = userModel.Email!,
                EmailConfirmed = true
            };
            var res = await _userManager.CreateAsync(user, userModel.Password!);
            if (!res.Succeeded) { return new AuthModel { Message = "Error" }; }
            var newUser = await _userManager.FindByEmailAsync(user.Email);
            var refreshToken = GeneraterRefreshToken(newUser!.Id);
            object value = await _db.RefreshTokens.AddAsync(refreshToken);
            if (!res.Succeeded) { return new AuthModel { Message = "Error in Create User" }; }
            await _userManager.AddToRoleAsync(user, "Employee");
            var token = await CreateJwtSecurityToken(user);
            await _userManager.UpdateAsync(user);
            var back = new AuthModel
            {
                Message = "Every thing is ok",
                IsAuthanticated = true,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Roles = await _userManager.GetRolesAsync(user),
                Email = userModel.Email!,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpireson = refreshToken.Expirson
            };
            return back;
        }
    }

    //Seed
    public class Seed
    {
        public static void Setting(WebApplicationBuilder builder)
        {
            builder.Services.Configure<JWTValues>(builder.Configuration.GetSection("JWT"));
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(opt => {
                opt.RequireHttpsMetadata = false;
                opt.SaveToken = false;
                opt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidIssuer = builder.Configuration["JWT:Issuer"],
                    ValidAudience = builder.Configuration["JWT:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]!))
                };
            });
            builder.Services.AddIdentity<IdentityUser, IdentityRole>(opt =>
            {
                //SingIn
                opt.SignIn.RequireConfirmedEmail = false;
                opt.SignIn.RequireConfirmedPhoneNumber = false;
                opt.SignIn.RequireConfirmedAccount = false;
                //Password
                opt.Password.RequireDigit = false;
                opt.Password.RequiredLength = 6;
                opt.Password.RequiredUniqueChars = 0;
                opt.Password.RequireNonAlphanumeric = false;
                opt.Password.RequireUppercase = false;
                opt.Password.RequireLowercase = false;
            }).AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
            builder.Services.AddTransient<IAuthServies, AuthServies>();
            builder.Services.AddTransient<IEmailSender, EmailSender>(a =>
                          new EmailSender(
                              builder.Configuration["EmailSender:Host"]!,
                              builder.Configuration.GetValue<int>("EmailSender:Port"),
                              builder.Configuration.GetValue<bool>("EmailSender:EnableSSL"),
                              builder.Configuration["EmailSender:UserName"]!,
                              builder.Configuration["EmailSender:Password"]!
                          )
                      );
        }
        public static async Task AddRoll(IServiceProvider provider, List<string> roles)
        {
            var scopFactory = provider.GetRequiredService<IServiceScopeFactory>();
            var role = scopFactory.CreateScope();
            var ro = role.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            foreach (string roleName in roles)
            {
                if (!await ro.RoleExistsAsync(roleName))
                {
                    IdentityRole rol = new IdentityRole { Name = roleName, NormalizedName = roleName };
                    await ro.CreateAsync(rol);
                }
            }
        }
        public static async Task AddAdmin(IServiceProvider provider, string email)
        {
            var scopFactory = provider.GetRequiredService<IServiceScopeFactory>();
            var user = scopFactory.CreateScope();
            var us = user.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
            if (await us.FindByEmailAsync(email) == null)
            {
                IdentityUser rol = new IdentityUser
                {
                    Email = email,
                    UserName = email,
                    EmailConfirmed = true,
                };
                await us.CreateAsync(rol, "Qweasd12#");
            }

        }
    }
}


