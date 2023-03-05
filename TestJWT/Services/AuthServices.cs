using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestJWT.Helpers;
using TestJWT.Models;

namespace TestJWT.Services
{
    public class AuthServices : IAuthServices
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;

        public AuthServices(UserManager<ApplicationUser> userManager, IOptions<JWT> jwt, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _jwt = jwt.Value;
            _roleManager = roleManager;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null|| !await _roleManager.RoleExistsAsync(model.Role))
            {
                return "Invalid userId or role";
            }

            if (await _userManager.IsInRoleAsync(user,model.Role))
            {
                return "user is already assign to this role";

            }
            var result=await _userManager.AddToRoleAsync(user,model.Role);

            return result.Succeeded? string.Empty: "something went wrong";
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            var authModel=new AuthModel();

            var user=await _userManager.FindByEmailAsync(model.Email);



            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password) )
            {
                authModel.Message = "Email or Password is incorrect";
                return authModel;

            }

            var JwtSecurityToken = await CreateJwtToken(user);


            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken);
            authModel.Email = user.Email;
            authModel.UserName = user.UserName;
            authModel.ExpireOn = JwtSecurityToken.ValidTo;


            var roleResult = await _userManager.GetRolesAsync(user);
            authModel.Roles=roleResult.ToList();

            return authModel;
        
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
            {
                return new AuthModel { Message = "Email is already exsit" };
            }
            if (await _userManager.FindByNameAsync(model.USerName) is not null)
            {
                return new AuthModel { Message = "USerName is already exsit" };
            }

            var user = new ApplicationUser
            {
                UserName = model.USerName,
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
            };
           var result= await _userManager.CreateAsync(user,model.Passsword);

            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description} , ";
                }
                return new AuthModel { Message = errors };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var JwtSecurityToken = await CreateJwtToken(user);
            return new AuthModel
            {
                Email = user.Email,
                ExpireOn=JwtSecurityToken.ValidTo,
                IsAuthenticated=true,
                Roles=new List<string> {"User" },
                Token=new JwtSecurityTokenHandler().WriteToken(JwtSecurityToken),   
                UserName=user.UserName,
            };
        }
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
