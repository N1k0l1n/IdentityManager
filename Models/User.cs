﻿using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class User : IdentityUser
    {
        [Required]
        public string Name { get; set; }
    }
}
