using Microsoft.EntityFrameworkCore;

namespace TestJWT.Models
{
    [Owned]
    public class RefreshToken
    {
        public string Token { get; set; }

        public DateTime ExpiresOn { get; set; }
        public DateTime CreatedOn { get; set; }
        public DateTime? RevokedOn { get; set; }

        public bool IsExpired => DateTime.Now >= ExpiresOn;
        public bool IsActived => RevokedOn==null && !IsExpired;
    }
}
