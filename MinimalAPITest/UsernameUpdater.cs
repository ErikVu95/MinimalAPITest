namespace MinimalAPITest
{
    public class UsernameUpdater
    {
        private readonly string filePath;

        public UsernameUpdater(string filePath)
        {
            this.filePath = filePath;
        }

        public bool UpdateUsername(string userId, string newUsername)
        {
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
