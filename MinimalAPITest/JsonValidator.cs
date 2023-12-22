using Newtonsoft.Json;

namespace MinimalAPITest
{
    public class JsonValidator
    {
        public static bool IsValidJson(string json)
        {
            try
            {
                JsonConvert.DeserializeObject(json);
                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }
    }
}