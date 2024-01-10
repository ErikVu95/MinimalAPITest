using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

using MinimalAPITest;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<UserService>();

// lese på nytt på login og prøve å finne ut hvordan man sletter token helt
var usersFilePath = Path.Combine(builder.Environment.ContentRootPath, "Users.txt");
UserFileLoader userFileLoader = new UserFileLoader(usersFilePath);
//var users = userFileLoader.LoadUsersFromFile();

UsernameUpdater usernameUpdater = new UsernameUpdater(usersFilePath);
PasswordUpdater passwordUpdater = new PasswordUpdater(usersFilePath);

var key = Encoding.ASCII.GetBytes("this_is_a_test_secret_key_1234567890");

builder.Services.AddAuthorization();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
        };
    });

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();

app.UseCors(builder =>
{
    builder.AllowAnyOrigin()
           .AllowAnyHeader()
           .AllowAnyMethod();
           //.AllowCredentials();

    //builder.WithOrigins("http://127.0.0.1:5500")
});

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPost("/login", (LoginData loginData, HttpContext context) =>
{
    var users = new UserFileLoader(usersFilePath).LoadUsersFromFile();

    var user = users.FirstOrDefault(u => u.Username == loginData.Username && u.Password == loginData.Password);

    if (user != null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
                //new Claim(ClaimTypes.NameIdentifier, user.UserID),
                new Claim("userId", user.UserID),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("access", user.Access),
            }),
            Expires = DateTime.UtcNow.AddMinutes(20),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        Console.WriteLine($"Logged in user: {user.Username}");

        context.Response.Cookies.Append("Token", tokenHandler.WriteToken(token), new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            Expires = tokenDescriptor.Expires ?? DateTime.UtcNow.AddMinutes(20),
        });


        return Results.Ok(new
        {
            Token = tokenHandler.WriteToken(token),
            Message = $"Welcome, {user.Username}! Access level: {user.Access}"
        });
    }
    else
    {
        if (users.Any(u => u.Username == loginData.Username))
        {
            return Results.BadRequest("Incorrect password");
        }
        else
        {
            return Results.BadRequest("Invalid username");
        }
    }
});

List<string> revokedTokens = [];
app.MapPost("/logout", (HttpContext context) =>
{
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

    try
    {
        revokedTokens.Add(token);
        return Results.Ok("Logout successful");
    }
    catch (Exception ex)
    {
        return Results.BadRequest("User is already logged out.");
    }
});

app.MapPut("/setUsername", async (HttpContext context) =>
{
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var userInput = "";
    var loggedInUserId = "";

    if (!ValidateToken(token) || revokedTokens.Contains(token))
    {
        return Results.BadRequest("Invalid or revoked token");
    }

    try
    {
        using (StreamReader reader = new StreamReader(context.Request.Body))
        {
            var bodyContent = await reader.ReadToEndAsync();

            var jsonBody = JsonConvert.DeserializeAnonymousType(bodyContent, new { newUsername = "" });
            userInput = jsonBody.newUsername;
        }

        // Extract Id from token
        var tokenHandler = new JwtSecurityTokenHandler();
        var jsonToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jsonToken != null)
        {
            var nameIdentifierClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "userId");

            if (nameIdentifierClaim != null)
            {
                loggedInUserId = nameIdentifierClaim.Value;
            }
            else
            {
                throw new InvalidOperationException("NameIdentifier claim not found in the token.");
            }
        }
        else
        {
            throw new InvalidOperationException("Invalid or unreadable token.");
        }

        usernameUpdater.UpdateUsername(loggedInUserId, userInput);

        
        return Results.Ok($"Username updated successfully. New username: {userInput}");
    }
    catch (Exception ex)
    {
        return Results.BadRequest($"Error processing request: {ex.Message}");
    }
});


app.MapPost("/setPassword", (HttpContext context) =>
{
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var users = new UserFileLoader(usersFilePath).LoadUsersFromFile();

    if (!ValidateToken(token) || revokedTokens.Contains(token))
    {
        return Results.BadRequest("Invalid or revoked token");
    }

    //if (!PasswordValidator.IsValidPassword(newPassword))
    //{
    //    return Results.BadRequest("Invalid password. Please ensure it meets the required criteria.");
    //}

    //if (userService.LoggedInUser != null)
    //{
    //    var userId = userService.LoggedInUser.UserID;
    //    var passwordUpdated = passwordUpdater.UpdatePassword(userId, newPassword);

    //    if (passwordUpdated)
    //    {
    //        userService.LoggedInUser.Password = newPassword;
    //        return Results.Ok("Password updated successfully.");
    //    }
    //    else
    //    {
    //        return Results.BadRequest("Password is the same as the existing one or user not found.");
    //    }
    //}
    //else
    //{
    //    return Results.BadRequest("User not logged in.");
    //}
    return Results.BadRequest();
});

app.MapGet("/getConfig", (HttpContext context) =>
{
    var configFilePath = Path.Combine(app.Environment.ContentRootPath, "Config.json");
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

    try
    {
        if (!File.Exists(configFilePath))
        {
            throw new FileNotFoundException("Config.json not found");
        }

        // Validate the token
        if (!ValidateToken(token) || revokedTokens.Contains(token))
        {
            throw new UnauthorizedAccessException("Invalid or revoked token");
        }
        var configJson = File.ReadAllText(configFilePath);

        return Results.Ok(configJson);
    }
    catch (FileNotFoundException ex)
    {
        return Results.NotFound($"Config.json not found: {ex.Message}");
    }
    catch (UnauthorizedAccessException ex)
    {
        return Results.BadRequest($"Invalid token: {ex.Message}");
    }
    catch (Exception ex)
    {
        return Results.BadRequest($"Error processing request: {ex.Message}");
    }
});


// Developer and admin
app.MapPost("/setConfig", (string newConfigJson, UserService userService) =>
{
    if (JsonValidator.IsValidJson(newConfigJson))
    {
        if (userService.LoggedInUser != null && (userService.LoggedInUser.Access == "admin" || userService.LoggedInUser.Access == "developer"))
        {
            try
            {
                File.WriteAllText("Config.json", newConfigJson);
                return Results.Ok("Configuration set successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error setting configuration: {ex}");
                return Results.BadRequest($"Error setting configuration: {ex.Message}");
            }
        }
        else
        {
            return Results.BadRequest("Insufficient access rights to set configuration.");
        }
    }
    else
    {
        return Results.BadRequest("Invalid JSON format.");
    }
});

// Admin only
app.MapGet("/getUsers", (HttpContext context) =>
{
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
    if (string.IsNullOrEmpty(token))
    {
        return Results.Forbid();
    }

    if (!ValidateToken(token) || revokedTokens.Contains(token))
    {
        return Results.BadRequest("Invalid or revoked token");
    }

    // Check if the logged-in user has admin access
    var loggedInUserAccessClaim = context.User?.FindFirst("access")?.Value;

    if (loggedInUserAccessClaim != null && loggedInUserAccessClaim == "admin")
    {
        if (File.Exists(usersFilePath))
        {
            var users = File.ReadAllLines(usersFilePath)
                .Select(line =>
                {
                    var parts = line.Split(',');
                    return new User
                    {
                        UserID = parts[0].Split('=')[1],
                        Username = parts[1].Split('=')[1],
                        Password = parts[2].Split('=')[1],
                        Access = parts[3].Split('=')[1]
                    };
                }).ToList();

            return Results.Ok(users);
        }
        else
        {
            return Results.BadRequest("The file Users.txt does not exist.");
        }
    }
    else
    {
        return Results.Forbid();
    }
});

bool ValidateToken(string token)
{
    if (string.IsNullOrEmpty(token))
    {
        Console.WriteLine("No token provided.");
        return false;
    }

    else if (revokedTokens.Contains(token))
    {
        Console.WriteLine("Token has been revoked.");
        return false;
    }

    var tokenHandler = new JwtSecurityTokenHandler();

    try
    {
        tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true, // Enable lifetime validation
            ClockSkew = TimeSpan.Zero,
        }, out SecurityToken validatedToken);

        return true;
    }
    catch (SecurityTokenExpiredException e)
    {
        Console.WriteLine(e.Message);
        return false;
    }
    catch (SecurityTokenMalformedException e)
    {
        Console.WriteLine("Token is malformed: " + e.Message);
        return false;
    }
    catch (SecurityTokenException e)
    {
        Console.WriteLine(e.Message);
        return false;
    }
}




// Admin only
app.MapPost("/addUser", (User newUser, UserService userService) =>
{
    //if (userService.LoggedInUser != null && userService.LoggedInUser.Access == "admin")
    //{
    //    string filePath = Path.Combine(app.Environment.ContentRootPath, "Users.txt");

    //    // Check if the UserID already exists
    //    if (users.Any(u => u.UserID == newUser.UserID))
    //    {
    //        return Results.BadRequest($"User with UserID {newUser.UserID} already exists.");
    //    }

    //    if (newUser.Access.ToLower() == "admin")
    //    {
    //        return Results.BadRequest("Admins cannot add other admins.");
    //    }

    //    if (!PasswordValidator.IsValidPassword(newUser.Password))
    //    {
    //        return Results.BadRequest("Invalid password. Please ensure it meets the required criteria.");
    //    }

    //    var userLine = $"UserID={newUser.UserID},Username={newUser.Username},Password={newUser.Password},Access={newUser.Access}";
    //    File.AppendAllLines(filePath, new[] { userLine });

    //    return Results.Ok($"User with UserID {newUser.UserID} added successfully.");
    //}
    //else
    //{
    //    return Results.BadRequest("Unauthorized access: Admin only");
    //}
});

// Admin only
app.MapDelete("/removeUser/{targetUserID}", (string targetUserID, UserService userService) =>
{
    if (userService.LoggedInUser != null && userService.LoggedInUser.Access == "admin")
    {
        var lines = File.ReadAllLines(usersFilePath).ToList();
        var lineToRemove = lines.FirstOrDefault(line => line.Contains($"UserID={targetUserID},"));

        if (lineToRemove != null)
        {
            lines.Remove(lineToRemove);

            // Write the updated lines back to the file
            File.WriteAllLines(usersFilePath, lines);

            return Results.Ok($"User with UserID {targetUserID} removed successfully.");
        }
        else
        {
            return Results.BadRequest($"User with UserID {targetUserID} not found.");
        }
    }
    else
    {
        return Results.BadRequest("Unauthorized access: Admin only");
    }
});

app.Run();
