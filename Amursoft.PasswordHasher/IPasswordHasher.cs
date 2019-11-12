namespace Amursoft.PasswordHasher
{
    public interface IPasswordHasher
    {
        string HashPassword(string password);

        PasswordVerificationResult VerifyHashedPassword(string hashedPassword, string password);
    }
}