namespace MinimalAPITest
{
    public class PasswordUpdater
    {
        private readonly string filePath;

        public PasswordUpdater(string filePath)
        {
            this.filePath = filePath;
        }

        public bool UpdatePassword(string userId, string newPassword)
        {
            var lines = File.ReadAllLines(filePath).ToList();

            for (int i = 0; i < lines.Count; i++)
            {
                if (lines[i].Contains($"UserID={userId},"))
                {
                    // Extract existing password
                    var existingPassword = lines[i].Split(',')
                        .FirstOrDefault(part => part.StartsWith("Password="))
                        ?.Split('=')[1];

                    // Update only if the new password is different
                    if (!string.Equals(existingPassword, newPassword, StringComparison.Ordinal))
                    {
                        lines[i] = lines[i].Replace($"Password={existingPassword}", $"Password={newPassword}");
                        File.WriteAllLines(filePath, lines);
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }

            return false;
        }
    }
}
