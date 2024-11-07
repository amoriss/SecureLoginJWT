using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace SecureLoginJWT.Controllers;
public class UserController : Controller
{
    public IActionResult Index()
    {
        return View();
    }

    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult Dashboard()
    {
        return View();
    }
}
