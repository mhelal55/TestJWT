using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestJWT.Models;
using TestJWT.Services;

namespace TestJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthServices _authServices;

        public AuthController(IAuthServices authServices)
        {
            _authServices = authServices;
        }
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result = await _authServices.RegisterAsync(model);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }
            
                SetRefreshTokenToCookies(result.RefreshToken, result.RefreshTokenExpiration);
            
            return Ok(result);
        }
        [HttpPost("token")]
        public async Task<IActionResult> GetTokenAsync([FromBody]TokenRequestModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result= await _authServices.GetTokenAsync(model);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                SetRefreshTokenToCookies(result.RefreshToken, result.RefreshTokenExpiration);
            }

            return Ok(result);
        }

            [HttpPost("addrole")]
        public async Task<IActionResult> AddRoleAsync([FromBody]AddRoleModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var result= await _authServices.AddRoleAsync(model);

            if (!string.IsNullOrEmpty(result))
            {
                return BadRequest(result);
            }

            return Ok(model);
        }

        private void SetRefreshTokenToCookies(string RefreshToken,DateTime Expires)
        {
            var cookiesOptions = new CookieOptions { 
               HttpOnly= true,
               Expires= Expires.ToLocalTime(),
            };
            Response.Cookies.Append("cookiesOptions", RefreshToken, cookiesOptions);
        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refrshToken = Request.Cookies["cookiesOptions"];

            var result=await _authServices.RefreshTokenAsync(refrshToken);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result);
            }

            SetRefreshTokenToCookies(result.RefreshToken, result.RefreshTokenExpiration);  
            
            return Ok(result);
        }

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model) {

            var token = model.token??Request.Cookies["cookiesOptions"];

            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Token is required");
            }
            var result=await _authServices.RevokeTokenAsync(token);

            if (!result)
            {
                return BadRequest("Token is Invalid");
            }

            return Ok();
        }


    }
}
