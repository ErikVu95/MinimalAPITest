using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace MinimalAPITest
{
    public class TokenValidator
    {
        public static readonly List<string> revokedTokens = new List<string>();
        private static readonly byte[] key = Encoding.ASCII.GetBytes(AppSettings.SecretKey);

        public static bool ValidateToken(string token)
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
            catch (SecurityTokenInvalidLifetimeException e)
            {
                Console.WriteLine("Token has an invalid lifetime: " + e.Message);
                return false;
            }
            catch (SecurityTokenSignatureKeyNotFoundException e)
            {
                Console.WriteLine("Token has an invalid signature key: " + e.Message);
                return false;
            }
            catch (SecurityTokenInvalidSignatureException e)
            {
                Console.WriteLine("Token has an invalid signature: " + e.Message);
                return false;
            }
            catch (SecurityTokenException e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
            catch (Exception e)
            {
                Console.WriteLine("An unexpected error occurred during token validation: " + e.Message);
                return false;
            }
        }
    }
}
