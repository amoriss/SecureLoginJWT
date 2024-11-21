﻿using System.ComponentModel.DataAnnotations;

namespace SecureLoginJWT.Models;

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    public string? ConfirmPassword { get; set; }
}
