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
    public async Task<ActionResult> Login(LoginModel model)
    {

        if(!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userRepository.GetUserByUsernameAsync(model.Username);

        if (user == null)
        {
            ModelState.AddModelError("", "Invalid username or password.");
            return View(model);
        }

        using var sha256 = SHA256.Create();
        var hashedPassword = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(model.Password)));

        if (user.PasswordHash != hashedPassword)
        {
            ModelState.AddModelError("", "Invalid username or password.");
            return View(model);
        }

        // call method that Generates JWT TOken
        var token = GenerateJwtToken(user.Username);

        // Add token to response or send it to the client securely (part of cookie or JSON response)
        HttpContext.Response.Headers.Add("Authorization", $"Bearer {token}");

        return RedirectToAction("Index", "Home");


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
    public async Task<IActionResult> Register(RegisterModel model)
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
            PasswordHash = hashedPassword,
            Email = model.Email
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
