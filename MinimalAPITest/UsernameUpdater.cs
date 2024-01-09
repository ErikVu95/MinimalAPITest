namespace MinimalAPITest
{
    public class UsernameUpdater
    {
        private readonly string filePath;

        public UsernameUpdater(string filePath)
        {
            this.filePath = filePath;
        }

        public void UpdateUsername(string userId, string newUsername)
        {
            if (string.IsNullOrWhiteSpace(newUsername))
            {
                throw new ArgumentException("New username cannot be null or whitespace.");
            }

            var lines = File.ReadAllLines(filePath).ToList();

            for (int i = 0; i < lines.Count; i++)
            {
                if (lines[i].Contains($"UserID={userId},"))
                {
                    // Extract existing username
                    var existingUsername = lines[i].Split(',')
                        .FirstOrDefault(part => part.StartsWith("Username="))
                        ?.Split('=')[1];

                    // Update only if the new username is different
                    if (!string.Equals(existingUsername, newUsername, StringComparison.OrdinalIgnoreCase))
                    {
                        lines[i] = lines[i].Replace($"Username={existingUsername}", $"Username={newUsername}");
                        File.WriteAllLines(filePath, lines);
                        return;
                    }
                    else
                    {
                        throw new InvalidOperationException("New username is the same as the existing username.");
                    }
                }
            }

            throw new KeyNotFoundException("User ID not found or username update failed.");
        }
    }
}
