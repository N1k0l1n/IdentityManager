using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class LoginDTO
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }


        [Display(Name = "Remeber me?")]
        public bool RemeberMe { get; set;}
    }
}
