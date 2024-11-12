using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SecureLoginJWT.Data;
using SecureLoginJWT.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SecureLoginJWT.Controllers;
public class AccountController : Controller
{
    private readonly UserRepository _userRepository;

    public AccountController(UserRepository userRepository)
    {
        _userRepository = userRepository;
    }
    public IActionResult Index()
    {
        return View();
    }

    // GET
    public ActionResult Login()
    {
        return View();
    }
    // POST
    [HttpPost]
    public ActionResult Login(LoginModel model)
    {
        if (model.Username == "admin" && model.Password == "password")
        {
            var token = GenerateJwtToken(model.Username);

            Response.Cookies.Append("auth_token", token, new CookieOptions
            {
                HttpOnly = true,  // cookie is not accessible via JavaScript (added security)
                Secure = false,
                SameSite = SameSiteMode.Strict  // protection against Cross-Site Forgery
            });

            return RedirectToAction("Dashboard", "User");
        }
        return View(model);
    }

    // Generate JWT Token
    private string GenerateJwtToken(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes("TopSuperSecureSecretKey1234567890");

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) }), // add claims (username) to the token
            Expires = DateTime.UtcNow.AddMinutes(1), // token's expiration time
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature) // signs the token using secret key
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(LoginModel model)
    {
        if(!ModelState.IsValid)
        {
            return View(model);
        }

        using var sha256 = SHA256.Create();
        var hashedPassword = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(model.Password)));

        var user = new UserCredentials
        {
            Username = model.Username,
            PasswordHash = hashedPassword
        };

        var success = await _userRepository.RegisterUserAsync(user);
        if(success)
        {
            return RedirectToAction("Login", "Account");
        }

        ModelState.AddModelError("", "Registration failed");
        return View(model);
    }
}
