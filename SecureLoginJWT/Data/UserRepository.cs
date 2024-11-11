using MySqlConnector;
using SecureLoginJWT.Models;

namespace SecureLoginJWT.Data;

public class UserRepository
{
    private readonly string _connectionString;
    public UserRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<bool> RegisterUserAsync(UserCredentials user)
    {
        using var connection = new MySqlConnection(_connectionString);
        await connection.OpenAsync();

        var query = "INSERT INTO user_credentials (username, email, password_hash) VALUES (@Username, @Email, @PasswordHash)";

        using var command = new MySqlCommand(query, connection);
        command.Parameters.AddWithValue("@Username", user.Username);
        command.Parameters.AddWithValue("@Email", user.Email);
        command.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);

        var result = await command.ExecuteNonQueryAsync();
        return result > 0;
    }

    public async Task<UserCredentials?> GetUserByUsernameAsync(string username)
    {
        using var connection = new MySqlConnection(_connectionString);
        await connection.OpenAsync();

        var query = "SELECT id, username, email, password_hash FROM user_credentials WHERE username =@Username";

        using var command = new MySqlCommand(query, connection);
        command.Parameters.AddWithValue("@Username", username);

        using var reader = await command.ExecuteReaderAsync();
        if(await reader.ReadAsync())
        {
            return new UserCredentials
            {
                Id = reader.GetInt32("id"),
                Username = reader.GetString("username"),
                Email = reader.GetString("email"),
                PasswordHash = reader.GetString("password")
            };
        }
        return null;
    }
}
