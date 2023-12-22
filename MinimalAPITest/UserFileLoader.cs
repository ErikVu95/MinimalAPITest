using MinimalAPITest;

public class UserFileLoader
{
    private readonly string filePath;

    public UserFileLoader(string filePath)
    {
        this.filePath = filePath;
    }

    public List<User> LoadUsersFromFile()
    {
        var userList = new List<User>();

        if (File.Exists(filePath))
        {
            using (var reader = new StreamReader(filePath))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var parts = line.Split(',');

                    var user = new User();

                    foreach (var part in parts)
                    {
                        var keyValue = part.Split('=');
                        var key = keyValue[0];
                        var value = keyValue[1];

                        switch (key)
                        {
                            case "UserID":
                                user.UserID = value;
                                break;
                            case "Username":
                                user.Username = value;
                                break;
                            case "Password":
                                user.Password = value;
                                break;
                            case "Access":
                                user.Access = value;
                                break;
                        }
                    }

                    userList.Add(user);
                }
            }
        }
        else
        {
            Console.WriteLine($"The file {filePath} does not exist.");
        }

        return userList;
    }
}
