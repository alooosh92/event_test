using System.ComponentModel.DataAnnotations;

namespace event_test.VModels
{
    public class VMShowEvent
    {
        [Required] public string? Name { get; set; }
        [Required] public string? Description { get; set; }
        [Required] public string? Location { get; set; }
        [Required] public double? Late { get; set; } //for map location
        [Required] public double? Long { get; set; } // for map location
        [Required] public DateTime? EventDate { get; set; }
        [Required] public int EventTicket { get; set; }
    }
}
