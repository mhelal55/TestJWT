using System.ComponentModel.DataAnnotations;

namespace TestJWT.Models
{
    public class RegisterModel
    {
        [Required,MaxLength(100)]
        public string FirstName { get; set; }
        [Required, MaxLength(100)]
        public string LastName { get; set; }
        [Required, MaxLength(50)]
        public string USerName { get; set; }
        [Required, MaxLength(128)]
        [EmailAddress]
        public string Email { get; set; }
        [Required, MaxLength(256)]
        public string Passsword { get; set; }
    }
}
