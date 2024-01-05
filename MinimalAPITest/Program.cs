using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

using MinimalAPITest;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<UserService>();

var filePath = Path.Combine(builder.Environment.ContentRootPath, "Users.txt");

UserFileLoader userFileLoader = new UserFileLoader(filePath);
var users = userFileLoader.LoadUsersFromFile();

UsernameUpdater usernameUpdater = new UsernameUpdater(filePath);
PasswordUpdater passwordUpdater = new PasswordUpdater(filePath);

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
    //builder.AllowAnyOrigin()
    //       .AllowAnyHeader()
    //       .AllowAnyMethod();
    builder.WithOrigins("http://127.0.0.1:5500")
           .AllowAnyHeader()
           .AllowAnyMethod();
});

app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapPost("/login", (LoginData loginData, HttpContext ctx) =>
{
    var user = users.FirstOrDefault(u => u.Username == loginData.Username && u.Password == loginData.Password);

    if (user != null)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.UserID),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim("access", user.Access),
            }),
            Expires = DateTime.UtcNow.AddMinutes(30),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        Console.WriteLine($"Logged in user: {user.Username}");
        var accessClaim = tokenDescriptor.Subject?.FindFirst("access");
        Console.WriteLine(token);

        ctx.Response.Headers.Add("Authorization", $"Bearer {tokenHandler.WriteToken(token)}");

        return Results.Ok(new
        {
            Token = tokenHandler.WriteToken(token),
            Message = $"Welcome, {user.Username}! Access level: {user.Access}"
        });
    }
    else
    {
        return Results.BadRequest("Invalid username or password");
    }
});


//app.MapPost("/login", (LoginData loginData, UserService userService) =>
//{
//    var user = users.FirstOrDefault(u => u.Username == loginData.Username && u.Password == loginData.Password);

//    if (user != null)
//    {
//        var tokenHandler = new JwtSecurityTokenHandler();
//        var tokenDescriptor = new SecurityTokenDescriptor
//        {
//            Subject = new ClaimsIdentity(new[] { new Claim("userId", user.UserID) }),
//            Expires = DateTime.UtcNow.AddMinutes(30),
//            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
//        };
//        var token = tokenHandler.CreateToken(tokenDescriptor);

//        userService.LoggedInUser = user;
//        Console.WriteLine($"Logged in user: {userService.LoggedInUser?.Username}");

//        return Results.Ok(new { Token = tokenHandler.WriteToken(token), Message = $"Welcome, {user.Username}! Access level: {user.Access}" });
//    }
//    else
//    {
//        return Results.BadRequest("Invalid username or password");
//    }
//});

app.MapPost("/logout", (UserService userService) =>
{
    userService.LoggedInUser = null;
    return Results.Ok("Logout successful");
});

app.MapPost("/setUsername", (string newUsername, UserService userService) =>
{
    if (string.IsNullOrWhiteSpace(newUsername))
    {
        return Results.BadRequest("Username cannot be empty or whitespace.");
    }

    if (userService.LoggedInUser != null)
    {
        var userId = userService.LoggedInUser.UserID;
        var usernameUpdated = usernameUpdater.UpdateUsername(userId, newUsername);

        if (usernameUpdated)
        {
            userService.LoggedInUser.Username = newUsername;
            return Results.Ok($"Username updated to: {newUsername}");
        }
        else
        {
            return Results.BadRequest($"Username '{newUsername}' is the same as the existing one or user not found.");
        }
    }
    else
    {
        return Results.BadRequest("User not logged in.");
    }
});


app.MapPost("/setPassword", (string newPassword, UserService userService) =>
{
    if (!PasswordValidator.IsValidPassword(newPassword))
    {
        return Results.BadRequest("Invalid password. Please ensure it meets the required criteria.");
    }

    if (userService.LoggedInUser != null)
    {
        var userId = userService.LoggedInUser.UserID;
        var passwordUpdated = passwordUpdater.UpdatePassword(userId, newPassword);

        if (passwordUpdated)
        {
            userService.LoggedInUser.Password = newPassword;
            return Results.Ok("Password updated successfully.");
        }
        else
        {
            return Results.BadRequest("Password is the same as the existing one or user not found.");
        }
    }
    else
    {
        return Results.BadRequest("User not logged in.");
    }
});

app.MapGet("/getConfig", () =>
{
    var filePath = Path.Combine(app.Environment.ContentRootPath, "Config.json");

    if (File.Exists(filePath))
    {
        try
        {
            var configJson = File.ReadAllText(filePath);
            return Results.Ok(configJson);
        }
        catch (Exception ex)
        {
            return Results.BadRequest($"Error reading Config.json: {ex.Message}");
        }
    }
    else
    {
        return Results.BadRequest("Config.json not found.");
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
app.MapGet("/getUsers", (HttpContext ctx) =>
{
    var loggedInUserAccessClaim = ctx.User?.FindFirst("access")?.Value;

    // Check if the logged-in user has admin access
    if (loggedInUserAccessClaim != null && loggedInUserAccessClaim == "admin")
    {
        if (File.Exists(filePath))
        {
            var users = File.ReadAllLines(filePath)
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

// Admin only
app.MapPost("/addUser", (User newUser, UserService userService) =>
{
    if (userService.LoggedInUser != null && userService.LoggedInUser.Access == "admin")
    {
        string filePath = Path.Combine(app.Environment.ContentRootPath, "Users.txt");

        // Check if the UserID already exists
        if (users.Any(u => u.UserID == newUser.UserID))
        {
            return Results.BadRequest($"User with UserID {newUser.UserID} already exists.");
        }

        if (newUser.Access.ToLower() == "admin")
        {
            return Results.BadRequest("Admins cannot add other admins.");
        }

        if (!PasswordValidator.IsValidPassword(newUser.Password))
        {
            return Results.BadRequest("Invalid password. Please ensure it meets the required criteria.");
        }

        var userLine = $"UserID={newUser.UserID},Username={newUser.Username},Password={newUser.Password},Access={newUser.Access}";
        File.AppendAllLines(filePath, new[] { userLine });

        return Results.Ok($"User with UserID {newUser.UserID} added successfully.");
    }
    else
    {
        return Results.BadRequest("Unauthorized access: Admin only");
    }
});

// Admin only
app.MapDelete("/removeUser/{targetUserID}", (string targetUserID, UserService userService) =>
{
    if (userService.LoggedInUser != null && userService.LoggedInUser.Access == "admin")
    {
        var lines = File.ReadAllLines(filePath).ToList();
        var lineToRemove = lines.FirstOrDefault(line => line.Contains($"UserID={targetUserID},"));

        if (lineToRemove != null)
        {
            lines.Remove(lineToRemove);

            // Write the updated lines back to the file
            File.WriteAllLines(filePath, lines);

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
