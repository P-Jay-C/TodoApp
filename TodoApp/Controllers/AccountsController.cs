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
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using TodoApp.Configuration;
using TodoApp.DTOs.Incoming;
using TodoApp.DTOs.Outgoing;

namespace TodoApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountsController : ControllerBase
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;

        public AccountsController(
            UserManager<IdentityUser> userManager, 
        IOptionsMonitor<JwtConfig> optionMonitor )
        {
            this._userManager = userManager;
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
                        var jwtToken = GenerateJwtToken(newUser);

                        return Ok(new RegistrationResponse()
                        {
                            Success = true,
                            Token = jwtToken
                        });
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
                    var jwtToken = GenerateJwtToken(existingUser);

                    return Ok(new RegistrationResponse()
                    {
                        Success = true,
                        Token = jwtToken
                    });
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
        private string GenerateJwtToken(IdentityUser user)
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
                Expires = DateTime.UtcNow.AddHours(6),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);
            

        return jwtToken;
    }
    }
} 