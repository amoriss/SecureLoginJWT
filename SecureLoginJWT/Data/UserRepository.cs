using MySqlConnector;
using SecureLoginJWT.Models;
using Microsoft.EntityFrameworkCore;

namespace SecureLoginJWT.Data;

public class UserRepository
{
    private readonly ApplicationDbContext _context;
    public UserRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<bool> RegisterUserAsync(UserCredentials user)
    {
        await _context.UserCredentials.AddAsync(user);
        var result = await _context.SaveChangesAsync();
        return result > 0;
    }

    public async Task<UserCredentials?> GetUserByUsernameAsync(string username)
    {
        return await _context.UserCredentials.FirstOrDefaultAsync(u => u.Username == username);
    }
}
