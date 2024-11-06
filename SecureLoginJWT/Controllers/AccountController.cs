using Microsoft.AspNetCore.Mvc;

namespace SecureLoginJWT.Controllers;
public class AccountController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}
