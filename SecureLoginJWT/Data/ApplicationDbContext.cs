using Microsoft.EntityFrameworkCore;
using SecureLoginJWT.Models;

namespace SecureLoginJWT.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options): base (options)
    {
            
    }

    public DbSet<UserCredentials> UserCredentials { get; set; }
}
