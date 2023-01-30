using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using TodoApp.Configuration;
using TodoApp.Data;
using TodoApp.DTOs.Incoming;
using TodoApp.DTOs.Outgoing;
using TodoApp.Models;

namespace TodoApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")] 
    public class AccountsController : ControllerBase  
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly AppDbContext _context;
        private readonly JwtConfig _jwtConfig;

        public AccountsController(
            UserManager<IdentityUser> userManager, 
        IOptionsMonitor<JwtConfig> optionMonitor,
            TokenValidationParameters tokenValidationParameters,
            AppDbContext context)
        {
            this._userManager = userManager;
            _tokenValidationParameters = tokenValidationParameters;
            _context = context;
            _jwtConfig = optionMonitor.CurrentValue;
            
        }

        [HttpPost]
        [Route("Register")]

        public async Task<IActionResult> Register ([FromBody] UserRegistrationDto userRegistration){

                if(ModelState.IsValid)
                {

                    var existingUser = await _userManager.FindByEmailAsync(userRegistration.Email);

                    if (existingUser != null)
                    {
                        return BadRequest(new RegistrationResponse()
                        {
                            Errors = new List<string>()
                            {
                                "Email already in use"
                            },
                            Success = false
                        });
                    }

                    var newUser = new IdentityUser()
                    {
                        Email = userRegistration.Email,
                        UserName = userRegistration.UserName
                    };


                    var isCreated = await _userManager.CreateAsync(newUser, userRegistration.Password);
                    if (isCreated.Succeeded)
                    {
                        var jwtToken = await GenerateJwtToken(newUser);

                        return Ok(jwtToken);
                    }
                    else
                    {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors =   isCreated.Errors.Select(x=> x.Description).ToList(),
                        Success = false
                    });
                }
                }

            return BadRequest(new RegistrationResponse(){
                Errors = new List<string>(){
                    "Invalid Payload"
                },
                Success = false,
            });
        }

        [HttpPost]
        [Route("Login")]

        public async Task<IActionResult> Login(UserLoginDto userLogin)
        {

            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(userLogin.Email);
                if (existingUser == null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>(){
                            "User does not exist"
                        },
                        Success = false,
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, userLogin.Password);

                if (isCorrect)
                {
                    var jwtToken = await GenerateJwtToken(existingUser);

                    return Ok(jwtToken);
                }
                else
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "Password does not match."
                        }
                    });
                }

                
            }else{
                return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>(){
                    "Invalid Payload"
                },
                Success = false,
            });
            }
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequestDto tokenRequest)
        {
            if (ModelState.IsValid)
            {
               var result = await VerifyAndGenerateToken(tokenRequest);
               if (result==null)
               {
                   return BadRequest(new RegistrationResponse()
                   {
                       Success = false,
                       Errors = new List<string>()
                       {
                           "Invalid Tokens"
                       }
                   });
                }

               return Ok(result);
            }
           
            
                return BadRequest(new RegistrationResponse()
                {
                    Success = false,
                    Errors = new List<string>()
                    {
                        "Invalid Payload"
                    }
                }); 
        }

        public async Task<AuthResult> VerifyAndGenerateToken(TokenRequestDto tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                //Validation 1 - Validate JWT token format
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters,out var validatedToken);


                // Validation 2 - Validate Encryption format
                // Check if it has been encrypted with same security algorithm
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                        StringComparison.InvariantCulture);

                    if (result == false)
                        return null;
                };

                // Validation 3 - Validate Expiry Date
                var utcExpiryDate = long.Parse(tokenInVerification.Claims
                    .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)!.Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "Token has not yet expired"
                        }
                    };
                }

                // Validation  - Validate Existence of token
                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);
                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "Token does not exits"
                        }
                    };
                }

                ;

                // Validation 5 - Validate if used

                if (storedToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "Token has been used"
                        }
                    };
                }

                // Validation 6 - Validate if revoked
                if (storedToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "Token has been revoked"
                        }
                    };
                }

                // Validation 7 -  Validate Id
                var jti = tokenInVerification.Claims.FirstOrDefault(x=>x.Type == JwtRegisteredClaimNames.Jti)!.Value;

                if (storedToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Success = false,
                        Errors = new List<string>()
                        {
                            "Token does not match"
                        }
                    };
                }

                // Update current token 

                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                // Generate new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser);
            }
            catch (Exception e)
            { 
                return null;
            }

        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var DateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            DateTimeVal = DateTimeVal.AddSeconds(unixTimeStamp).ToLocalTime();
            return DateTimeVal;
        }

            public async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new []
                {
                    new Claim("id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddSeconds(30),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                AddedDate = DateTime.UtcNow,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                ExpiryDate = DateTime.Now.AddMonths(6),
                Token = RandomString(35) + Guid.NewGuid()
            };
            await _context.RefreshTokens.AddAsync(refreshToken);
            await  _context.SaveChangesAsync();

            return new AuthResult()
            {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }

        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZO123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }
    }
} 