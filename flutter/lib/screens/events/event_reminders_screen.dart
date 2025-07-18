import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:koutu/providers/event_reminder_provider.dart';
import 'package:koutu/services/notification/event_reminder_service.dart';
import 'package:koutu/widgets/common/error_view.dart';
import 'package:koutu/widgets/common/loading_indicator.dart';
import 'package:intl/intl.dart';

class EventRemindersScreen extends ConsumerStatefulWidget {
  const EventRemindersScreen({super.key});

  @override
  ConsumerState<EventRemindersScreen> createState() => _EventRemindersScreenState();
}

class _EventRemindersScreenState extends ConsumerState<EventRemindersScreen> {
  final _dateFormat = DateFormat('MMM d, yyyy');
  final _timeFormat = DateFormat('h:mm a');
  
  @override
  Widget build(BuildContext context) {
    final remindersAsync = ref.watch(eventRemindersProvider);
    
    return Scaffold(
      appBar: AppBar(
        title: const Text('Event Reminders'),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => const EventReminderSettingsScreen(),
                ),
              );
            },
          ),
        ],
      ),
      body: remindersAsync.when(
        data: (reminders) {
          if (reminders.isEmpty) {
            return Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.event_note,
                    size: 64,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No event reminders',
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  const Text('Add events to get outfit reminders'),
                  const SizedBox(height: 24),
                  ElevatedButton.icon(
                    onPressed: () => _showAddEventDialog(context),
                    icon: const Icon(Icons.add),
                    label: const Text('Add Event'),
                  ),
                ],
              ),
            );
          }
          
          return ListView.builder(
            padding: const EdgeInsets.all(16),
            itemCount: reminders.length + 1,
            itemBuilder: (context, index) {
              if (index == 0) {
                return _buildUpcomingEventsHeader(context);
              }
              
              final reminder = reminders[index - 1];
              return _EventReminderCard(
                reminder: reminder,
                onEdit: () => _showEditEventDialog(context, reminder),
                onDelete: () => _deleteReminder(reminder.id),
              );
            },
          );
        },
        loading: () => const Center(child: LoadingIndicator()),
        error: (error, stack) => ErrorView(
          error: error.toString(),
          onRetry: () => ref.refresh(eventRemindersProvider),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _showAddEventDialog(context),
        child: const Icon(Icons.add),
      ),
    );
  }
  
  Widget _buildUpcomingEventsHeader(BuildContext context) {
    final upcomingAsync = ref.watch(upcomingEventsProvider(7));
    
    return upcomingAsync.when(
      data: (events) {
        if (events.isEmpty) return const SizedBox.shrink();
        
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'UPCOMING THIS WEEK',
              style: Theme.of(context).textTheme.labelSmall,
            ),
            const SizedBox(height: 8),
            Container(
              height: 120,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                itemCount: events.length,
                itemBuilder: (context, index) {
                  final event = events[index];
                  return _UpcomingEventCard(event: event);
                },
              ),
            ),
            const SizedBox(height: 24),
            Text(
              'ALL EVENTS',
              style: Theme.of(context).textTheme.labelSmall,
            ),
            const SizedBox(height: 8),
          ],
        );
      },
      loading: () => const SizedBox.shrink(),
      error: (_, __) => const SizedBox.shrink(),
    );
  }
  
  Future<void> _showAddEventDialog(BuildContext context) async {
    final result = await showDialog<EventReminder>(
      context: context,
      builder: (context) => const EventReminderDialog(),
    );
    
    if (result != null && mounted) {
      ref.refresh(eventRemindersProvider);
    }
  }
  
  Future<void> _showEditEventDialog(
    BuildContext context,
    EventReminder reminder,
  ) async {
    final result = await showDialog<EventReminder>(
      context: context,
      builder: (context) => EventReminderDialog(reminder: reminder),
    );
    
    if (result != null && mounted) {
      ref.refresh(eventRemindersProvider);
    }
  }
  
  Future<void> _deleteReminder(String reminderId) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Reminder'),
        content: const Text('Are you sure you want to delete this event reminder?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    
    if (confirmed == true && mounted) {
      final service = ref.read(eventReminderServiceProvider);
      final result = await service.deleteEventReminder(reminderId);
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to delete reminder: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ref.refresh(eventRemindersProvider);
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Reminder deleted'),
            ),
          );
        },
      );
    }
  }
}

/// Event reminder card widget
class _EventReminderCard extends StatelessWidget {
  final EventReminder reminder;
  final VoidCallback onEdit;
  final VoidCallback onDelete;
  
  const _EventReminderCard({
    required this.reminder,
    required this.onEdit,
    required this.onDelete,
  });
  
  @override
  Widget build(BuildContext context) {
    final dateFormat = DateFormat('EEE, MMM d');
    final timeFormat = DateFormat('h:mm a');
    final now = DateTime.now();
    final isUpcoming = reminder.eventDateTime.isAfter(now);
    
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: isUpcoming
              ? Theme.of(context).colorScheme.primaryContainer
              : Theme.of(context).colorScheme.surfaceVariant,
          child: Icon(
            _getEventIcon(reminder.eventType),
            color: isUpcoming
                ? Theme.of(context).colorScheme.primary
                : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
        title: Text(
          reminder.title,
          style: TextStyle(
            fontWeight: FontWeight.bold,
            decoration: isUpcoming ? null : TextDecoration.lineThrough,
          ),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${dateFormat.format(reminder.eventDateTime)} at ${timeFormat.format(reminder.eventDateTime)}',
            ),
            if (reminder.location != null)
              Text(
                '📍 ${reminder.location}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            if (reminder.dressCode != null)
              Text(
                '👔 ${reminder.dressCode}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ),
        trailing: PopupMenuButton<String>(
          onSelected: (value) {
            if (value == 'edit') {
              onEdit();
            } else if (value == 'delete') {
              onDelete();
            }
          },
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'edit',
              child: Text('Edit'),
            ),
            const PopupMenuItem(
              value: 'delete',
              child: Text('Delete'),
            ),
          ],
        ),
        isThreeLine: true,
        enabled: isUpcoming,
      ),
    );
  }
  
  IconData _getEventIcon(String eventType) {
    switch (eventType.toLowerCase()) {
      case 'work':
        return Icons.work;
      case 'party':
        return Icons.celebration;
      case 'date':
        return Icons.favorite;
      case 'wedding':
        return Icons.cake;
      case 'interview':
        return Icons.business_center;
      case 'meeting':
        return Icons.groups;
      case 'formal':
        return Icons.emoji_events;
      default:
        return Icons.event;
    }
  }
}

/// Upcoming event card widget
class _UpcomingEventCard extends StatelessWidget {
  final EventReminder event;
  
  const _UpcomingEventCard({required this.event});
  
  @override
  Widget build(BuildContext context) {
    final daysUntil = event.eventDateTime.difference(DateTime.now()).inDays;
    final timeFormat = DateFormat('h:mm a');
    
    return Container(
      width: 150,
      margin: const EdgeInsets.only(right: 12),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Icon(
                    _getEventIcon(event.eventType),
                    size: 20,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primaryContainer,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      daysUntil == 0
                          ? 'Today'
                          : daysUntil == 1
                              ? 'Tomorrow'
                              : 'In $daysUntil days',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: Theme.of(context).colorScheme.onPrimaryContainer,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                event.title,
                style: const TextStyle(fontWeight: FontWeight.bold),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
              const Spacer(),
              Text(
                timeFormat.format(event.eventDateTime),
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  IconData _getEventIcon(String eventType) {
    switch (eventType.toLowerCase()) {
      case 'work':
        return Icons.work;
      case 'party':
        return Icons.celebration;
      case 'date':
        return Icons.favorite;
      case 'wedding':
        return Icons.cake;
      case 'interview':
        return Icons.business_center;
      case 'meeting':
        return Icons.groups;
      case 'formal':
        return Icons.emoji_events;
      default:
        return Icons.event;
    }
  }
}

/// Event reminder dialog
class EventReminderDialog extends StatefulWidget {
  final EventReminder? reminder;
  
  const EventReminderDialog({
    super.key,
    this.reminder,
  });
  
  @override
  State<EventReminderDialog> createState() => _EventReminderDialogState();
}

class _EventReminderDialogState extends State<EventReminderDialog> {
  final _formKey = GlobalKey<FormState>();
  final _titleController = TextEditingController();
  final _locationController = TextEditingController();
  final _notesController = TextEditingController();
  final _dressCodeController = TextEditingController();
  
  late DateTime _selectedDate;
  late TimeOfDay _selectedTime;
  String _selectedEventType = 'Casual';
  ReminderTiming _selectedTiming = ReminderTiming.oneHourBefore;
  List<String> _selectedColors = [];
  
  final _eventTypes = [
    'Work',
    'Party',
    'Date',
    'Wedding',
    'Interview',
    'Meeting',
    'Formal',
    'Casual',
  ];
  
  final _colors = [
    'Black',
    'White',
    'Navy',
    'Gray',
    'Blue',
    'Red',
    'Pink',
    'Green',
    'Brown',
    'Beige',
  ];
  
  @override
  void initState() {
    super.initState();
    
    if (widget.reminder != null) {
      final reminder = widget.reminder!;
      _titleController.text = reminder.title;
      _locationController.text = reminder.location ?? '';
      _notesController.text = reminder.notes ?? '';
      _dressCodeController.text = reminder.dressCode ?? '';
      _selectedDate = reminder.eventDateTime;
      _selectedTime = TimeOfDay.fromDateTime(reminder.eventDateTime);
      _selectedEventType = reminder.eventType;
      _selectedTiming = reminder.reminderTiming;
      _selectedColors = reminder.preferredColors ?? [];
    } else {
      _selectedDate = DateTime.now().add(const Duration(days: 1));
      _selectedTime = const TimeOfDay(hour: 19, minute: 0);
    }
  }
  
  @override
  void dispose() {
    _titleController.dispose();
    _locationController.dispose();
    _notesController.dispose();
    _dressCodeController.dispose();
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 400),
        child: Scaffold(
          appBar: AppBar(
            title: Text(widget.reminder == null ? 'Add Event' : 'Edit Event'),
            automaticallyImplyLeading: false,
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Cancel'),
              ),
              TextButton(
                onPressed: _saveReminder,
                child: const Text('Save'),
              ),
            ],
          ),
          body: Form(
            key: _formKey,
            child: ListView(
              padding: const EdgeInsets.all(16),
              children: [
                // Title
                TextFormField(
                  controller: _titleController,
                  decoration: const InputDecoration(
                    labelText: 'Event Name',
                    hintText: 'e.g., Team Meeting',
                  ),
                  validator: (value) {
                    if (value == null || value.isEmpty) {
                      return 'Please enter event name';
                    }
                    return null;
                  },
                ),
                const SizedBox(height: 16),
                
                // Event Type
                DropdownButtonFormField<String>(
                  value: _selectedEventType,
                  decoration: const InputDecoration(
                    labelText: 'Event Type',
                  ),
                  items: _eventTypes.map((type) {
                    return DropdownMenuItem(
                      value: type,
                      child: Text(type),
                    );
                  }).toList(),
                  onChanged: (value) {
                    if (value != null) {
                      setState(() => _selectedEventType = value);
                    }
                  },
                ),
                const SizedBox(height: 16),
                
                // Date and Time
                Row(
                  children: [
                    Expanded(
                      child: ListTile(
                        title: const Text('Date'),
                        subtitle: Text(
                          DateFormat('MMM d, yyyy').format(_selectedDate),
                        ),
                        trailing: const Icon(Icons.calendar_today),
                        onTap: _selectDate,
                      ),
                    ),
                    Expanded(
                      child: ListTile(
                        title: const Text('Time'),
                        subtitle: Text(_selectedTime.format(context)),
                        trailing: const Icon(Icons.access_time),
                        onTap: _selectTime,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                
                // Location
                TextFormField(
                  controller: _locationController,
                  decoration: const InputDecoration(
                    labelText: 'Location (Optional)',
                    hintText: 'e.g., Conference Room A',
                    prefixIcon: Icon(Icons.location_on),
                  ),
                ),
                const SizedBox(height: 16),
                
                // Dress Code
                TextFormField(
                  controller: _dressCodeController,
                  decoration: const InputDecoration(
                    labelText: 'Dress Code (Optional)',
                    hintText: 'e.g., Business Casual',
                    prefixIcon: Icon(Icons.checkroom),
                  ),
                ),
                const SizedBox(height: 16),
                
                // Reminder Timing
                DropdownButtonFormField<ReminderTiming>(
                  value: _selectedTiming,
                  decoration: const InputDecoration(
                    labelText: 'Remind Me',
                    prefixIcon: Icon(Icons.notifications),
                  ),
                  items: ReminderTiming.values.map((timing) {
                    return DropdownMenuItem(
                      value: timing,
                      child: Text(_getTimingText(timing)),
                    );
                  }).toList(),
                  onChanged: (value) {
                    if (value != null) {
                      setState(() => _selectedTiming = value);
                    }
                  },
                ),
                const SizedBox(height: 16),
                
                // Preferred Colors
                const Text(
                  'Preferred Colors (Optional)',
                  style: TextStyle(fontSize: 16),
                ),
                const SizedBox(height: 8),
                Wrap(
                  spacing: 8,
                  children: _colors.map((color) {
                    return FilterChip(
                      label: Text(color),
                      selected: _selectedColors.contains(color),
                      onSelected: (selected) {
                        setState(() {
                          if (selected) {
                            _selectedColors.add(color);
                          } else {
                            _selectedColors.remove(color);
                          }
                        });
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: 16),
                
                // Notes
                TextFormField(
                  controller: _notesController,
                  decoration: const InputDecoration(
                    labelText: 'Notes (Optional)',
                    hintText: 'Any additional details...',
                  ),
                  maxLines: 3,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
  
  Future<void> _selectDate() async {
    final date = await showDatePicker(
      context: context,
      initialDate: _selectedDate,
      firstDate: DateTime.now(),
      lastDate: DateTime.now().add(const Duration(days: 365)),
    );
    
    if (date != null) {
      setState(() => _selectedDate = date);
    }
  }
  
  Future<void> _selectTime() async {
    final time = await showTimePicker(
      context: context,
      initialTime: _selectedTime,
    );
    
    if (time != null) {
      setState(() => _selectedTime = time);
    }
  }
  
  String _getTimingText(ReminderTiming timing) {
    switch (timing) {
      case ReminderTiming.tenMinutesBefore:
        return '10 minutes before';
      case ReminderTiming.thirtyMinutesBefore:
        return '30 minutes before';
      case ReminderTiming.oneHourBefore:
        return '1 hour before';
      case ReminderTiming.twoHoursBefore:
        return '2 hours before';
      case ReminderTiming.oneDayBefore:
        return '1 day before';
      case ReminderTiming.twoDaysBefore:
        return '2 days before';
      case ReminderTiming.oneWeekBefore:
        return '1 week before';
    }
  }
  
  Future<void> _saveReminder() async {
    if (!_formKey.currentState!.validate()) return;
    
    final eventDateTime = DateTime(
      _selectedDate.year,
      _selectedDate.month,
      _selectedDate.day,
      _selectedTime.hour,
      _selectedTime.minute,
    );
    
    final service = context.read(eventReminderServiceProvider);
    
    if (widget.reminder == null) {
      // Create new reminder
      final result = await service.createEventReminder(
        title: _titleController.text,
        eventDateTime: eventDateTime,
        eventType: _selectedEventType,
        location: _locationController.text.isEmpty ? null : _locationController.text,
        notes: _notesController.text.isEmpty ? null : _notesController.text,
        dressCode: _dressCodeController.text.isEmpty ? null : _dressCodeController.text,
        preferredColors: _selectedColors.isEmpty ? null : _selectedColors,
        reminderTiming: _selectedTiming,
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to create reminder: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (reminder) {
          Navigator.pop(context, reminder);
        },
      );
    } else {
      // Update existing reminder
      final result = await service.updateEventReminder(
        reminderId: widget.reminder!.id,
        title: _titleController.text,
        eventDateTime: eventDateTime,
        eventType: _selectedEventType,
        location: _locationController.text.isEmpty ? null : _locationController.text,
        notes: _notesController.text.isEmpty ? null : _notesController.text,
        dressCode: _dressCodeController.text.isEmpty ? null : _dressCodeController.text,
        preferredColors: _selectedColors.isEmpty ? null : _selectedColors,
        reminderTiming: _selectedTiming,
      );
      
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to update reminder: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (reminder) {
          Navigator.pop(context, reminder);
        },
      );
    }
  }
}

/// Event reminder settings screen
class EventReminderSettingsScreen extends ConsumerStatefulWidget {
  const EventReminderSettingsScreen({super.key});

  @override
  ConsumerState<EventReminderSettingsScreen> createState() => 
      _EventReminderSettingsScreenState();
}

class _EventReminderSettingsScreenState 
    extends ConsumerState<EventReminderSettingsScreen> {
  late EventReminderSettings _settings;
  
  @override
  void initState() {
    super.initState();
    _settings = ref.read(eventReminderServiceProvider).getSettings();
  }
  
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Event Reminder Settings'),
        actions: [
          TextButton(
            onPressed: _saveSettings,
            child: const Text('Save'),
          ),
        ],
      ),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text('Enable Event Reminders'),
            subtitle: const Text('Get notified before your events'),
            value: _settings.enabled,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(enabled: value);
              });
            },
          ),
          SwitchListTile(
            title: const Text('Include Outfit Recommendations'),
            subtitle: const Text('Get outfit suggestions with reminders'),
            value: _settings.includeRecommendations,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(includeRecommendations: value);
              });
            },
          ),
          SwitchListTile(
            title: const Text('Notify for All Events'),
            subtitle: const Text('Get reminders for all event types'),
            value: _settings.notifyForAllEvents,
            onChanged: (value) {
              setState(() {
                _settings = _settings.copyWith(notifyForAllEvents: value);
              });
            },
          ),
          
          if (!_settings.notifyForAllEvents) ...[
            const Divider(),
            const Padding(
              padding: EdgeInsets.all(16),
              child: Text(
                'Enabled Event Types',
                style: TextStyle(
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
            ),
            ...['Work', 'Party', 'Date', 'Wedding', 'Interview', 'Meeting', 'Formal', 'Casual']
                .map((type) {
              return CheckboxListTile(
                title: Text(type),
                value: _settings.enabledEventTypes.contains(type),
                onChanged: (value) {
                  setState(() {
                    final types = List<String>.from(_settings.enabledEventTypes);
                    if (value == true) {
                      types.add(type);
                    } else {
                      types.remove(type);
                    }
                    _settings = _settings.copyWith(enabledEventTypes: types);
                  });
                },
              );
            }).toList(),
          ],
        ],
      ),
    );
  }
  
  Future<void> _saveSettings() async {
    final service = ref.read(eventReminderServiceProvider);
    final result = await service.updateSettings(_settings);
    
    if (mounted) {
      result.fold(
        (failure) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to save settings: ${failure.message}'),
              backgroundColor: Colors.red,
            ),
          );
        },
        (_) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Settings saved'),
            ),
          );
          Navigator.pop(context);
        },
      );
    }
  }
}