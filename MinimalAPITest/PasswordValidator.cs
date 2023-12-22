using System.Text.RegularExpressions;

namespace MinimalAPITest;

public class PasswordValidator
{
    public static bool IsValidPassword(string password)
    {
        // Check if the password is null or empty
        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        // Check if the password is at least 12 characters long
        if (password.Length < 12)
        {
            return false;
        }

        int fulfilledConditions = 0;

        // Special letters (non-alphanumeric)
        if (Regex.IsMatch(password, @"[^\w\d]"))
        {
            fulfilledConditions++;
        }

        // Capital letter
        if (password.Any(char.IsUpper))
        {
            fulfilledConditions++;
        }

        // Number
        if (password.Any(char.IsDigit))
        {
            fulfilledConditions++;
        }

        return fulfilledConditions >= 2;
    }

}
