using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace event_test.Models
{
    public class Booking
    {
        [Key] public Guid Id { get; set; } = Guid.NewGuid();
        [Required] public Event? Event { get; set; }
        [Required] public IdentityUser? User { get; set; }
        [Required] public int NumTicket { get; set; }
    }
}
