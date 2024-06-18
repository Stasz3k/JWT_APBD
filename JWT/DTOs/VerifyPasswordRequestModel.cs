namespace JWT.DTOs
{
    public class VerifyPasswordRequestModel
    {
        public string Password { get; set; } = null!;
        public string Hash { get; set; } = null!;
    }
}
