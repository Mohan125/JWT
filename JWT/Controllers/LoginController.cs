using JWT.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private readonly IConfiguration config;


        public LoginController(IConfiguration config)
        {
            this.config = config;
        }
        

        [HttpPost("log")]
        public IActionResult Login([FromBody] loginModel login)
        {
            if(login.UserName == "Admin" && login.Password == "p")
            {
                var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.GetSection("TokenAuthentication:SecretKey").Value));

                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    
                    issuer: config.GetSection("TokenAuthentication:Issuer").Value,
                    null,
                    expires: DateTime.Now.AddMinutes(20),
                    claims: new List<Claim> { new Claim(ClaimTypes.Role,"Admin")},
                    signingCredentials:credentials
                    
                    
                    );

                var stringToken = new JwtSecurityTokenHandler().WriteToken(token);

                return Ok(new { Success = true, token = stringToken });

                 

            }
            else if(login.UserName == "user" && login.Password == "p")
            {
                var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.GetSection("TokenAuthentication:SecretKey").Value));

                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(

                    issuer: config.GetSection("TokenAuthentication:Issuer").Value,
                    null,
                    expires: DateTime.Now.AddMinutes(20),
                    claims: new List<Claim> { new Claim(ClaimTypes.Role, "GeneralUser") },
                    signingCredentials: credentials


                    );

                var stringToken = new JwtSecurityTokenHandler().WriteToken(token);

                return Ok(new { Success = true, token = stringToken });



            }
            return Unauthorized();
        }

    }
}
