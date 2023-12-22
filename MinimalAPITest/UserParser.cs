namespace MinimalAPITest
{
    public class UserParser
    {
        public static User ParseUserFromRequestBody(string requestBody)
        {
            var parts = requestBody.Split(',');

            var user = new User();

            foreach (var part in parts)
            {
                var keyValue = part.Split('=');

                // Check if keyValue has at least two elements
                if (keyValue.Length >= 2)
                {
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
            }
            return user;
        }
    }
}
