using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace event_test.VModels
{
    public class VMEvent
    {
        [Required] public string? EnName { get; set; }
        [Required] public string? ArName { get; set; }
        [Required] public string? EnDescription { get; set; }
        [Required] public string? ArDescription { get; set; }
        [Required] public string? EnLocation { get; set; }
        [Required] public string? ArLocation { get; set; }
        [Required] public double? Late { get; set; } //for map location
        [Required] public double? Long { get; set; } // for map location
        [Required] public DateTime? EventDate { get; set; }
        [Required] public int EventTicket { get; set; }
    }
}
