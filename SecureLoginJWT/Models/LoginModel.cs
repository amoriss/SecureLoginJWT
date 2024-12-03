using System.ComponentModel.DataAnnotations;

namespace SecureLoginJWT.Models;

public class LoginModel
{
    [Required(ErrorMessage = "Username is required.")]
    public string Username { get; set; }
    public string Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [DataType(DataType.Password)]
    public string Password { get; set; }

    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    public string? ConfirmPassword { get; set; }
}
