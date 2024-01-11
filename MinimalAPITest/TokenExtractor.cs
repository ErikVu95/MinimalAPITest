using System.IdentityModel.Tokens.Jwt;

namespace MinimalAPITest
{
    public class TokenExtractor
    {
        public static string ExtractUserIdFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            if (jsonToken != null)
            {
                var nameIdentifierClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "userId");

                if (nameIdentifierClaim != null)
                {
                    return nameIdentifierClaim.Value;
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
        }
    }

}
