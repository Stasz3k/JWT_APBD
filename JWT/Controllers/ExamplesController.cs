using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using JWT.DTOs;
using JWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ExamplesController : ControllerBase
    {
        private readonly IConfiguration _config;
        private static readonly List<User> Users = new List<User>();

        public ExamplesController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet("hash-password-without-salt/{password}")]
        public IActionResult HashPassword(string password)
        {
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                new byte[] { 0 },
                10,
                HashAlgorithmName.SHA512,
                128
            );

            return Ok(Convert.ToHexString(hash));
        }

        [HttpGet("hash-password/{password}")]
        public IActionResult HashPasswordWithSalt(string password)
        {
            var passwordHasher = new PasswordHasher<User>();
            return Ok(passwordHasher.HashPassword(new User(), password));
        }

        [HttpPost("verify-password")]
        public IActionResult VerifyPassword(VerifyPasswordRequestModel requestModel)
        {
            var passwordHasher = new PasswordHasher<User>();
            return Ok(passwordHasher.VerifyHashedPassword(new User(), requestModel.Hash, requestModel.Password) == PasswordVerificationResult.Success);
        }

        [HttpPost("register")]
        public IActionResult Register(RegisterRequestModel model)
        {
            var passwordHasher = new PasswordHasher<User>();
            var hashedPassword = passwordHasher.HashPassword(new User(), model.Password);

            var user = new User
            {
                Name = model.Username,
                Password = hashedPassword
            };

            Users.Add(user);

            return Ok(new { message = "User registered successfully" });
        }

        [HttpPost("login")]
        public IActionResult Login(LoginRequestModel model)
        {
            var user = Users.SingleOrDefault(u => u.Name == model.UserName);

            if (user == null)
            {
                return Unauthorized("Wrong username or password");
            }

            var passwordHasher = new PasswordHasher<User>();
            var passwordVerificationResult = passwordHasher.VerifyHashedPassword(user, user.Password, model.Password);

            if (passwordVerificationResult != PasswordVerificationResult.Success)
            {
                return Unauthorized("Wrong username or password");
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["JWT:Key"]!);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[] {
                    new System.Security.Claims.Claim("sub", model.UserName)
                }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _config["JWT:Issuer"],
                Audience = _config["JWT:Audience"]
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var stringToken = tokenHandler.WriteToken(token);

            var refTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[] {
                    new System.Security.Claims.Claim("sub", model.UserName)
                }),
                Expires = DateTime.UtcNow.AddDays(3),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _config["JWT:RefIssuer"],
                Audience = _config["JWT:RefAudience"]
            };

            var refToken = tokenHandler.CreateToken(refTokenDescriptor);
            var stringRefToken = tokenHandler.WriteToken(refToken);


            return Ok(new LoginResponseModel
            {
                Token = stringToken,
                RefreshToken = stringRefToken
            });
        }

        [HttpPost("refresh")]
        public IActionResult RefreshToken(RefreshTokenRequestModel requestModel)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_config["JWT:RefKey"]!);

            try
            {
                tokenHandler.ValidateToken(requestModel.RefreshToken, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = _config["JWT:RefIssuer"],
                    ValidAudience = _config["JWT:RefAudience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                }, out SecurityToken validatedToken);


                var newTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new System.Security.Claims.ClaimsIdentity(new[] {
                        new System.Security.Claims.Claim("sub", ((JwtSecurityToken)validatedToken).Claims.FirstOrDefault(c => c.Type == "sub")?.Value)
                    }),
                    Expires = DateTime.UtcNow.AddMinutes(15),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:Key"]!)), SecurityAlgorithms.HmacSha256Signature),
                    Issuer = _config["JWT:Issuer"],
                    Audience = _config["JWT:Audience"]
                };

                var newToken = tokenHandler.CreateToken(newTokenDescriptor);
                var newStringToken = tokenHandler.WriteToken(newToken);

                return Ok(new
                {
                    Token = newStringToken
                });
            }
            catch
            {
                return Unauthorized();
            }
        }
    }
}
